use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::cloudflare::DnsProvider;
use crate::config::RecordConfig;
use crate::error::{Result, UpdaterError};
use crate::logging;
use crate::tplink::WanIpProvider;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CycleReport {
    pub wan_ip: Option<Ipv4Addr>,
    pub zone_lookups: usize,
    pub records_checked: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub failed: usize,
    pub elapsed: Duration,
}

impl CycleReport {
    /// Reports whether the full desired DNS state was reconciled without an independent record failure.
    pub fn succeeded(&self) -> bool {
        self.failed == 0
            && self.wan_ip.is_some()
            && self.records_checked == self.created + self.updated + self.unchanged
    }

    /// Formats stable operational counts for Service Manager output and A/B evidence.
    pub fn summary(&self) -> String {
        format!(
            "cycle_complete success={} wan_ip={} zones={} checked={} unchanged={} created={} updated={} failed={} elapsed_ms={}",
            self.succeeded(),
            self.wan_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "none".into()),
            self.zone_lookups,
            self.records_checked,
            self.unchanged,
            self.created,
            self.updated,
            self.failed,
            self.elapsed.as_millis()
        )
    }
}

pub struct Reconciler<'a, W: WanIpProvider, D: DnsProvider> {
    wan_provider: &'a W,
    dns_provider: &'a D,
    records: &'a [RecordConfig],
}

impl<'a, W: WanIpProvider, D: DnsProvider> Reconciler<'a, W, D> {
    /// Composes providers and the immutable desired-record inventory for one or more cycles.
    pub fn new(wan_provider: &'a W, dns_provider: &'a D, records: &'a [RecordConfig]) -> Self {
        Self {
            wan_provider,
            dns_provider,
            records,
        }
    }

    /// Reads WAN state, caches each zone lookup, and independently reconciles every configured record.
    pub fn run_cycle(&self) -> Result<CycleReport> {
        let started = Instant::now();
        logging::info(format!("cycle_start records={}", self.records.len()));
        let wan_ip = self.wan_provider.read_wan_ipv4()?;
        ensure_publishable_wan_ipv4(wan_ip)?;
        logging::info(format!("wan_ipv4={wan_ip}"));
        let mut report = CycleReport {
            wan_ip: Some(wan_ip),
            ..CycleReport::default()
        };
        let mut zones: HashMap<String, std::result::Result<String, String>> = HashMap::new();
        for record in self.records {
            let zone = resolve_cached_zone(
                self.dns_provider,
                &record.zone_name,
                &mut zones,
                &mut report,
            );
            match zone.and_then(|zone_id| self.reconcile_record(zone_id, record, wan_ip)) {
                Ok(RecordAction::Unchanged) => report.unchanged += 1,
                Ok(RecordAction::Created) => report.created += 1,
                Ok(RecordAction::Updated) => report.updated += 1,
                Err(error) => {
                    report.failed += 1;
                    logging::error(format!(
                        "record={} zone={} failed={error}",
                        record.record_name, record.zone_name
                    ));
                }
            }
            report.records_checked += 1;
        }
        report.elapsed = started.elapsed();
        logging::info(report.summary());
        Ok(report)
    }

    /// Applies create, update, or no-op semantics to one exact A record.
    fn reconcile_record(
        &self,
        zone_id: &str,
        record: &RecordConfig,
        wan_ip: Ipv4Addr,
    ) -> std::result::Result<RecordAction, String> {
        let existing = self
            .dns_provider
            .find_a_record(zone_id, &record.record_name)
            .map_err(|error| error.to_string())?;
        match existing {
            None => {
                self.dns_provider
                    .create_a_record(zone_id, &record.record_name, wan_ip)
                    .map_err(|error| error.to_string())?;
                logging::info(format!(
                    "record={} action=created ip={wan_ip}",
                    record.record_name
                ));
                Ok(RecordAction::Created)
            }
            Some(existing) if existing.content == wan_ip => {
                logging::info(format!(
                    "record={} action=unchanged ip={wan_ip}",
                    record.record_name
                ));
                Ok(RecordAction::Unchanged)
            }
            Some(existing) => {
                self.dns_provider
                    .update_a_record(zone_id, &existing, wan_ip)
                    .map_err(|error| error.to_string())?;
                logging::info(format!(
                    "record={} action=updated from={} to={wan_ip}",
                    record.record_name, existing.content
                ));
                Ok(RecordAction::Updated)
            }
        }
    }
}

enum RecordAction {
    Unchanged,
    Created,
    Updated,
}

/// Refuses to publish a router reading that could never be reached from the public internet.
///
/// A TP-Link WAN interface reports `0.0.0.0` while a lease is renegotiating, and reports an
/// RFC 1918 or RFC 6598 address when it sits behind another router or carrier-grade NAT. Writing
/// any of those to the managed records takes every hostname offline until the next real change,
/// so a nonsense reading fails the cycle and leaves DNS exactly as it was.
pub fn ensure_publishable_wan_ipv4(address: Ipv4Addr) -> Result<()> {
    let octets = address.octets();
    let reason = if address.is_unspecified() {
        Some("unspecified")
    } else if address.is_loopback() {
        Some("loopback")
    } else if address.is_private() {
        Some("private")
    } else if address.is_link_local() {
        Some("link-local")
    } else if address.is_broadcast() {
        Some("broadcast")
    } else if address.is_multicast() {
        Some("multicast")
    } else if octets[0] == 100 && (64..128).contains(&octets[1]) {
        Some("carrier-grade NAT")
    } else if octets[0] == 198 && (18..20).contains(&octets[1]) {
        Some("benchmarking")
    } else if octets[0] >= 240 {
        Some("reserved")
    } else {
        None
    };
    match reason {
        None => Ok(()),
        Some(reason) => Err(UpdaterError::Protocol(format!(
            "TP-Link router reported a non-routable WAN address ({reason}); DNS was left unchanged"
        ))),
    }
}

/// Resolves each distinct zone once and caches a printable failure for dependent records.
fn resolve_cached_zone<'a, D: DnsProvider>(
    provider: &D,
    zone_name: &str,
    zones: &'a mut HashMap<String, std::result::Result<String, String>>,
    report: &mut CycleReport,
) -> std::result::Result<&'a str, String> {
    if !zones.contains_key(zone_name) {
        report.zone_lookups += 1;
        zones.insert(
            zone_name.to_owned(),
            provider
                .resolve_zone_id(zone_name)
                .map_err(|error| error.to_string()),
        );
    }
    zones
        .get(zone_name)
        .expect("zone inserted above")
        .as_ref()
        .map(String::as_str)
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use crate::cloudflare::DnsRecord;
    use crate::error::UpdaterError;

    use super::*;

    struct FakeWan(Result<Ipv4Addr>);

    impl WanIpProvider for FakeWan {
        /// Returns the deterministic WAN fixture supplied by the test.
        fn read_wan_ipv4(&self) -> Result<Ipv4Addr> {
            self.0
                .as_ref()
                .map(Clone::clone)
                .map_err(|error| UpdaterError::Protocol(error.to_string()))
        }
    }

    #[derive(Default)]
    struct FakeDns {
        zone_calls: RefCell<Vec<String>>,
        records: RefCell<HashMap<String, Option<DnsRecord>>>,
        writes: RefCell<Vec<String>>,
    }

    impl DnsProvider for FakeDns {
        /// Records and resolves every requested test zone.
        fn resolve_zone_id(&self, zone_name: &str) -> Result<String> {
            self.zone_calls.borrow_mut().push(zone_name.into());
            Ok(format!("zone-{zone_name}"))
        }

        /// Returns the configured record fixture by exact name.
        fn find_a_record(&self, _zone_id: &str, record_name: &str) -> Result<Option<DnsRecord>> {
            Ok(self.records.borrow().get(record_name).cloned().flatten())
        }

        /// Records a create operation for later assertions.
        fn create_a_record(
            &self,
            _zone_id: &str,
            record_name: &str,
            _content: Ipv4Addr,
        ) -> Result<()> {
            self.writes
                .borrow_mut()
                .push(format!("create:{record_name}"));
            Ok(())
        }

        /// Records an update operation for later assertions.
        fn update_a_record(
            &self,
            _zone_id: &str,
            existing: &DnsRecord,
            _content: Ipv4Addr,
        ) -> Result<()> {
            self.writes
                .borrow_mut()
                .push(format!("update:{}", existing.name));
            Ok(())
        }
    }

    /// Verifies zone caching plus unchanged, update, and create decisions in one cycle.
    #[test]
    fn reconciles_all_actions_and_caches_zones() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 10);
        let wan = FakeWan(Ok(wan_ip));
        let dns = FakeDns::default();
        dns.records.borrow_mut().insert(
            "a.example.com".into(),
            Some(DnsRecord {
                id: "1".into(),
                name: "a.example.com".into(),
                content: wan_ip,
                proxied: true,
                ttl: 1,
            }),
        );
        dns.records.borrow_mut().insert(
            "b.example.com".into(),
            Some(DnsRecord {
                id: "2".into(),
                name: "b.example.com".into(),
                content: Ipv4Addr::new(198, 51, 100, 2),
                proxied: false,
                ttl: 120,
            }),
        );
        let records = vec![
            record("example.com", "a.example.com"),
            record("example.com", "b.example.com"),
            record("other.com", "other.com"),
        ];
        let report = Reconciler::new(&wan, &dns, &records).run_cycle().unwrap();
        assert_eq!(
            (
                report.unchanged,
                report.updated,
                report.created,
                report.zone_lookups
            ),
            (1, 1, 1, 2)
        );
        assert_eq!(
            dns.writes.borrow().as_slice(),
            ["update:b.example.com", "create:other.com"]
        );
    }

    /// Verifies every address family a router can wrongly report is refused before any write.
    #[test]
    fn rejects_non_global_wan_addresses() {
        let rejected = [
            [0, 0, 0, 0],
            [127, 0, 0, 1],
            [10, 0, 0, 1],
            [172, 16, 0, 1],
            [192, 168, 0, 1],
            [169, 254, 1, 1],
            [100, 64, 0, 1],
            [198, 18, 0, 1],
            [224, 0, 0, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ];
        for octets in rejected {
            let address = Ipv4Addr::from(octets);
            assert!(
                ensure_publishable_wan_ipv4(address).is_err(),
                "{address} should have been refused"
            );
        }
        for octets in [[38, 59, 218, 121], [8, 8, 8, 8], [99, 63, 255, 254]] {
            let address = Ipv4Addr::from(octets);
            assert!(
                ensure_publishable_wan_ipv4(address).is_ok(),
                "{address} should have been accepted"
            );
        }
    }

    /// Verifies a non-routable router reading fails the cycle without writing to any record.
    #[test]
    fn cycle_fails_without_writing_when_wan_is_not_global() {
        let wan = FakeWan(Ok(Ipv4Addr::new(0, 0, 0, 0)));
        let dns = FakeDns::default();
        let records = vec![record("example.com", "a.example.com")];
        let result = Reconciler::new(&wan, &dns, &records).run_cycle();
        assert!(matches!(result, Err(UpdaterError::Protocol(_))));
        assert!(dns.writes.borrow().is_empty());
        assert!(dns.zone_calls.borrow().is_empty());
    }

    /// Creates one concise desired-record fixture.
    fn record(zone_name: &str, record_name: &str) -> RecordConfig {
        RecordConfig {
            zone_name: zone_name.into(),
            record_name: record_name.into(),
        }
    }
}
