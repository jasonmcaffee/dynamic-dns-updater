use std::env;
use std::time::Duration;

use url::Url;

use crate::error::{Result, UpdaterError};

const DEFAULT_ROUTER_HOST: &str = "http://192.168.0.1";
const DEFAULT_CLOUDFLARE_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_INTERVAL_SECONDS: u64 = 300;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordConfig {
    pub zone_name: String,
    pub record_name: String,
}

#[derive(Clone)]
pub enum CloudflareAuth {
    ApiToken(String),
    GlobalKey { email: String, key: String },
}

#[derive(Clone)]
pub struct AppConfig {
    pub router_host: String,
    pub router_password: String,
    pub cloudflare_base_url: String,
    pub cloudflare_auth: CloudflareAuth,
    pub interval: Duration,
    pub http_timeout: Duration,
    pub records: Vec<RecordConfig>,
}

impl AppConfig {
    /// Loads `.env` and process environment values, then validates the complete production configuration.
    pub fn from_environment() -> Result<Self> {
        let _ = dotenvy::dotenv();
        Self::from_lookup(|key| env::var(key).ok())
    }

    /// Builds configuration through an injected lookup so tests never mutate the process environment.
    pub fn from_lookup<F>(lookup: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let router_password = required_value(&lookup, "TP_LINK_ROUTER_PASSWORD")?;
        let router_host = validated_origin(
            optional_value(&lookup, "TP_LINK_ROUTER_HOST", DEFAULT_ROUTER_HOST),
            "TP_LINK_ROUTER_HOST",
        )?;
        let cloudflare_base_url = validated_origin(
            optional_value(
                &lookup,
                "CLOUDFLARE_API_BASE_URL",
                DEFAULT_CLOUDFLARE_BASE_URL,
            ),
            "CLOUDFLARE_API_BASE_URL",
        )?;
        let cloudflare_auth = cloudflare_auth(&lookup)?;
        let interval = parsed_duration(
            &lookup,
            "DYNAMIC_DNS_INTERVAL_SECONDS",
            DEFAULT_INTERVAL_SECONDS,
        )?;
        let http_timeout = parsed_duration(
            &lookup,
            "DYNAMIC_DNS_HTTP_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )?;
        Ok(Self {
            router_host,
            router_password,
            cloudflare_base_url,
            cloudflare_auth,
            interval,
            http_timeout,
            records: default_records(),
        })
    }
}

/// Returns the exact production zone and record pairs retained from the Python updater.
pub fn default_records() -> Vec<RecordConfig> {
    [
        ("jasonmcaffee.com", "jasonmcaffee.com"),
        ("jasonmcaffee.com", "ai.jasonmcaffee.com"),
        ("jasonmcaffee.com", "media.jasonmcaffee.com"),
        ("jasonmcaffee.com", "media-backend.jasonmcaffee.com"),
        ("jasonmcaffee.com", "git.jasonmcaffee.com"),
        ("jasonmcaffee.com", "phone.jasonmcaffee.com"),
        ("jasonmcaffee.com", "taxes.jasonmcaffee.com"),
        // task-2059. The Rust agent tasks board, reached through the same proxy as the names above.
        // It is the first name here that a person signs in to rather than one the proxy fronts
        // without a credential, so the record being proxied matters more than usual: Cloudflare is
        // what terminates TLS, and a sign-in over plain HTTP to the origin would put a password on
        // the wire.
        ("jasonmcaffee.com", "tasks.jasonmcaffee.com"),
        // task-2195. The Bob McAffee tape archive. Its pages come from a Cloudflare Worker; its audio
        // comes from brl-sites on this machine through the proxy, so the record has to point here.
        ("jasonmcaffee.com", "bobmcaffee.jasonmcaffee.com"),
        // task-2257. Scripture, a signed in study site served by scripture-server through the proxy.
        // Like the tasks board, a person types a password into it, so the record must stay proxied
        // and Cloudflare must be what terminates TLS.
        ("jasonmcaffee.com", "scriptures.jasonmcaffee.com"),
        ("yogajhana.com", "yogajhana.com"),
        ("chordical.com", "chordical.com"),
        ("chordical.com", "www.chordical.com"),
        ("chordical.com", "api.chordical.com"),
        // task-1799. This zone held no records at all when these two were added, so the first cycle
        // takes the create path — which is the one that applies the `proxied: true` default, and the
        // site is behind Cloudflare exactly like every other name here.
        ("blackrainbowlabs.com", "blackrainbowlabs.com"),
        ("blackrainbowlabs.com", "www.blackrainbowlabs.com"),
        // task-1806. Unluminous, the product site. This zone also held no records when these two were
        // added, so the first cycle takes the create path — which is the one that applies the
        // `proxied: true` default, and the site is behind Cloudflare exactly like every other name here.
        ("unluminous.com", "unluminous.com"),
        ("unluminous.com", "www.unluminous.com"),
        // task-1809. Inillucent, the retrieval-engine product site. This zone held no records at all
        // when these two were added, so the first cycle takes the create path - which is the one that
        // applies the `proxied: true` default, and the site is behind Cloudflare like every other name.
        ("inillucent.com", "inillucent.com"),
        ("inillucent.com", "www.inillucent.com"),
    ]
    .into_iter()
    .map(|(zone_name, record_name)| RecordConfig {
        zone_name: zone_name.into(),
        record_name: record_name.into(),
    })
    .collect()
}

/// Reads a required non-empty configuration value without exposing its contents in the error.
fn required_value<F>(lookup: &F, key: &str) -> Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| UpdaterError::Config(format!("{key} is required")))
}

/// Reads an optional non-empty configuration value or returns the stable default.
fn optional_value<F>(lookup: &F, key: &str, default: &str) -> String
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// Selects preferred API-token authentication or validates the legacy global-key pair.
fn cloudflare_auth<F>(lookup: &F) -> Result<CloudflareAuth>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(token) = lookup("CLOUDFLARE_API_TOKEN").filter(|value| !value.trim().is_empty()) {
        return Ok(CloudflareAuth::ApiToken(token));
    }
    Ok(CloudflareAuth::GlobalKey {
        email: required_value(lookup, "CLOUDFLARE_EMAIL")?,
        key: required_value(lookup, "CLOUDFLARE_GLOBAL_KEY")?,
    })
}

/// Parses a positive whole-second duration and rejects zero or malformed values.
fn parsed_duration<F>(lookup: &F, key: &str, default: u64) -> Result<Duration>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = lookup(key).unwrap_or_else(|| default.to_string());
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| UpdaterError::Config(format!("{key} must be a positive integer")))?;
    if seconds == 0 {
        return Err(UpdaterError::Config(format!(
            "{key} must be greater than zero"
        )));
    }
    Ok(Duration::from_secs(seconds))
}

/// Validates an HTTP origin and removes a trailing slash for reliable endpoint composition.
fn validated_origin(value: String, key: &str) -> Result<String> {
    let parsed = Url::parse(&value)
        .map_err(|_| UpdaterError::Config(format!("{key} must be a valid HTTP URL")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(UpdaterError::Config(format!(
            "{key} must be an HTTP URL with a host"
        )));
    }
    Ok(value.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Creates a valid test lookup with non-secret fixture values.
    fn valid_values() -> HashMap<String, String> {
        HashMap::from([
            ("TP_LINK_ROUTER_PASSWORD".into(), "fixture-password".into()),
            ("CLOUDFLARE_GLOBAL_KEY".into(), "fixture-key".into()),
            ("CLOUDFLARE_EMAIL".into(), "fixture@example.com".into()),
        ])
    }

    /// Verifies production defaults and the exact retained record inventory.
    #[test]
    fn loads_defaults_and_all_records() {
        let values = valid_values();
        let config = AppConfig::from_lookup(|key| values.get(key).cloned()).unwrap();
        assert_eq!(config.interval, Duration::from_secs(300));
        assert_eq!(config.records.len(), 20);
        assert_eq!(
            config.records.last().unwrap().record_name,
            "www.inillucent.com"
        );
        // task-2059. Asserted by name rather than only by the count, so a record removed and
        // another added in the same edit cannot leave the count right and the inventory wrong.
        let jasonmcaffee: Vec<&str> = config
            .records
            .iter()
            .filter(|record| record.zone_name == "jasonmcaffee.com")
            .map(|record| record.record_name.as_str())
            .collect();
        assert!(jasonmcaffee.contains(&"tasks.jasonmcaffee.com"), "{jasonmcaffee:?}");
        assert!(jasonmcaffee.contains(&"bobmcaffee.jasonmcaffee.com"), "{jasonmcaffee:?}");
        assert!(jasonmcaffee.contains(&"scriptures.jasonmcaffee.com"), "{jasonmcaffee:?}");
        let black_rainbow: Vec<&str> = config
            .records
            .iter()
            .filter(|record| record.zone_name == "blackrainbowlabs.com")
            .map(|record| record.record_name.as_str())
            .collect();
        assert_eq!(
            black_rainbow,
            vec!["blackrainbowlabs.com", "www.blackrainbowlabs.com"]
        );
        let unluminous: Vec<&str> = config
            .records
            .iter()
            .filter(|record| record.zone_name == "unluminous.com")
            .map(|record| record.record_name.as_str())
            .collect();
        assert_eq!(unluminous, vec!["unluminous.com", "www.unluminous.com"]);
        let inillucent: Vec<&str> = config
            .records
            .iter()
            .filter(|record| record.zone_name == "inillucent.com")
            .map(|record| record.record_name.as_str())
            .collect();
        assert_eq!(inillucent, vec!["inillucent.com", "www.inillucent.com"]);
    }

    /// Verifies a scoped API token takes precedence without requiring global-key fields.
    #[test]
    fn prefers_api_token_authentication() {
        let values: HashMap<String, String> = HashMap::from([
            ("TP_LINK_ROUTER_PASSWORD".into(), "fixture-password".into()),
            ("CLOUDFLARE_API_TOKEN".into(), "fixture-token".into()),
        ]);
        let config = AppConfig::from_lookup(|key| values.get(key).cloned()).unwrap();
        assert!(matches!(
            config.cloudflare_auth,
            CloudflareAuth::ApiToken(_)
        ));
    }

    /// Verifies invalid zero intervals fail before the daemon starts.
    #[test]
    fn rejects_zero_interval() {
        let mut values = valid_values();
        values.insert("DYNAMIC_DNS_INTERVAL_SECONDS".into(), "0".into());
        let result = AppConfig::from_lookup(|key| values.get(key).cloned());
        assert!(matches!(result, Err(UpdaterError::Config(_))));
    }
}
