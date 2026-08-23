use std::io::Read;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::config::CloudflareAuth;
use crate::error::{Result, UpdaterError};

const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub content: Ipv4Addr,
}

pub trait DnsProvider {
    /// Resolves an exact Cloudflare zone name to its stable identifier.
    fn resolve_zone_id(&self, zone_name: &str) -> Result<String>;
    /// Finds an exact A record in a previously resolved zone.
    fn find_a_record(&self, zone_id: &str, record_name: &str) -> Result<Option<DnsRecord>>;
    /// Creates a proxied A record with automatic TTL.
    fn create_a_record(&self, zone_id: &str, record_name: &str, content: Ipv4Addr) -> Result<()>;
    /// Replaces an existing record with the desired proxied A-record representation.
    fn update_a_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record_name: &str,
        content: Ipv4Addr,
    ) -> Result<()>;
}

pub struct CloudflareClient {
    client: Client,
    base_url: String,
}

impl CloudflareClient {
    /// Creates a pooled, proxy-free TLS client with secret headers marked sensitive.
    pub fn new(base_url: String, auth: CloudflareAuth, timeout: Duration) -> Result<Self> {
        let headers = authentication_headers(auth)?;
        let client = Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .no_proxy()
            .build()
            .map_err(|source| UpdaterError::http("building Cloudflare client", source))?;
        Ok(Self { client, base_url })
    }

    /// Executes a request with bounded transient retries and parses a successful Cloudflare envelope.
    fn execute<T, F>(&self, operation: &str, build_request: F) -> Result<T>
    where
        T: DeserializeOwned,
        F: Fn() -> RequestBuilder,
    {
        let mut last_error = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match build_request().send() {
                Ok(response) if should_retry(response.status()) && attempt < MAX_ATTEMPTS => {
                    last_error = Some(format!("HTTP {}", response.status()));
                    thread::sleep(retry_delay(attempt));
                }
                Ok(response) => return parse_response(operation, response),
                Err(source)
                    if attempt < MAX_ATTEMPTS && (source.is_timeout() || source.is_connect()) =>
                {
                    last_error = Some(source.to_string());
                    thread::sleep(retry_delay(attempt));
                }
                Err(source) => return Err(UpdaterError::http(operation, source)),
            }
        }
        Err(UpdaterError::Api(format!(
            "{operation} failed after {MAX_ATTEMPTS} attempts: {}",
            last_error.unwrap_or_else(|| "unknown transient error".into())
        )))
    }
}

impl DnsProvider for CloudflareClient {
    /// Resolves one exact zone and rejects missing or ambiguous responses.
    fn resolve_zone_id(&self, zone_name: &str) -> Result<String> {
        let url = format!("{}/zones", self.base_url);
        let zones: Vec<ZoneResult> = self.execute("resolving Cloudflare zone", || {
            self.client.get(&url).query(&[("name", zone_name)])
        })?;
        let exact: Vec<_> = zones
            .into_iter()
            .filter(|zone| zone.name.eq_ignore_ascii_case(zone_name))
            .collect();
        match exact.as_slice() {
            [zone] => Ok(zone.id.clone()),
            [] => Err(UpdaterError::Api(format!(
                "Cloudflare zone {zone_name} was not found"
            ))),
            _ => Err(UpdaterError::Api(format!(
                "Cloudflare returned multiple exact zones for {zone_name}"
            ))),
        }
    }

    /// Finds one exact A record and rejects duplicate records rather than updating an arbitrary row.
    fn find_a_record(&self, zone_id: &str, record_name: &str) -> Result<Option<DnsRecord>> {
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        let records: Vec<RecordResult> = self.execute("listing Cloudflare DNS records", || {
            self.client
                .get(&url)
                .query(&[("type", "A"), ("name", record_name)])
        })?;
        let exact: Vec<_> = records
            .into_iter()
            .filter(|record| {
                record.name.eq_ignore_ascii_case(record_name) && record.record_type == "A"
            })
            .collect();
        match exact.as_slice() {
            [] => Ok(None),
            [record] => Ok(Some(record.try_into()?)),
            _ => Err(UpdaterError::Api(format!(
                "Cloudflare returned duplicate A records for {record_name}"
            ))),
        }
    }

    /// Creates a missing proxied A record while retaining Cloudflare automatic TTL.
    fn create_a_record(&self, zone_id: &str, record_name: &str, content: Ipv4Addr) -> Result<()> {
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        let body = RecordWrite::new(record_name, content);
        let _: RecordResult = self.execute("creating Cloudflare DNS record", || {
            self.client.post(&url).json(&body)
        })?;
        Ok(())
    }

    /// Updates an existing record by identifier with the complete desired A-record representation.
    fn update_a_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record_name: &str,
        content: Ipv4Addr,
    ) -> Result<()> {
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        let body = RecordWrite::new(record_name, content);
        let _: RecordResult = self.execute("updating Cloudflare DNS record", || {
            self.client.put(&url).json(&body)
        })?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    result: T,
    #[serde(default)]
    errors: Vec<ApiMessage>,
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct ZoneResult {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct RecordResult {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Serialize)]
struct RecordWrite<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    content: String,
    proxied: bool,
    ttl: u32,
}

impl RecordWrite<'_> {
    /// Creates the canonical representation used for both create and update operations.
    fn new(record_name: &str, content: Ipv4Addr) -> RecordWrite<'_> {
        RecordWrite {
            name: record_name,
            record_type: "A",
            content: content.to_string(),
            proxied: true,
            ttl: 1,
        }
    }
}

impl TryFrom<&RecordResult> for DnsRecord {
    type Error = UpdaterError;

    /// Validates Cloudflare content as IPv4 before it reaches reconciliation logic.
    fn try_from(value: &RecordResult) -> Result<Self> {
        let content = value.content.parse().map_err(|_| {
            UpdaterError::Protocol(format!(
                "Cloudflare A record {} returned invalid IPv4 content",
                value.name
            ))
        })?;
        Ok(Self {
            id: value.id.clone(),
            name: value.name.clone(),
            content,
        })
    }
}

/// Builds either scoped-token or legacy global-key headers without exposing values through debug output.
fn authentication_headers(auth: CloudflareAuth) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    match auth {
        CloudflareAuth::ApiToken(token) => {
            insert_sensitive_header(&mut headers, AUTHORIZATION, format!("Bearer {token}"))?
        }
        CloudflareAuth::GlobalKey { email, key } => {
            insert_sensitive_header(&mut headers, HeaderName::from_static("x-auth-email"), email)?;
            insert_sensitive_header(&mut headers, HeaderName::from_static("x-auth-key"), key)?;
        }
    }
    Ok(headers)
}

/// Inserts a validated sensitive header so request diagnostics redact credentials.
fn insert_sensitive_header(headers: &mut HeaderMap, name: HeaderName, value: String) -> Result<()> {
    let mut header = HeaderValue::from_str(&value).map_err(|_| {
        UpdaterError::Config(format!(
            "{} contains invalid header characters",
            name.as_str()
        ))
    })?;
    header.set_sensitive(true);
    headers.insert(name, header);
    Ok(())
}

/// Parses a bounded Cloudflare response and turns status/envelope errors into concise diagnostics.
fn parse_response<T: DeserializeOwned>(operation: &str, mut response: Response) -> Result<T> {
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| UpdaterError::Io {
            context: operation.into(),
            source,
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(UpdaterError::Api(format!(
            "{operation} returned an oversized response"
        )));
    }
    let envelope: ApiEnvelope<T> = serde_json::from_slice(&bytes)
        .map_err(|source| UpdaterError::serialization(operation, source))?;
    if !status.is_success() || !envelope.success {
        return Err(UpdaterError::Api(format!(
            "{operation} returned HTTP {status}: {}",
            format_api_errors(&envelope.errors)
        )));
    }
    Ok(envelope.result)
}

/// Formats only Cloudflare error codes/messages, excluding request headers and secret-bearing data.
fn format_api_errors(errors: &[ApiMessage]) -> String {
    if errors.is_empty() {
        return "no API error details".into();
    }
    errors
        .iter()
        .map(|error| format!("{} {}", error.code, error.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Identifies Cloudflare throttling and server failures that are safe to retry.
fn should_retry(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Returns a short exponential backoff suitable for a five-minute reconciliation daemon.
fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(200 * 2_u64.pow((attempt - 1) as u32))
}

#[cfg(test)]
mod tests {
    use std::thread::{self, JoinHandle};

    use tiny_http::{Response as TinyResponse, Server, StatusCode as TinyStatus};

    use super::*;

    /// Creates a Cloudflare client pointed at a local fixture server with non-secret authentication.
    fn fixture_client(base_url: String) -> CloudflareClient {
        CloudflareClient::new(
            base_url,
            CloudflareAuth::ApiToken("fixture-token".into()),
            Duration::from_secs(2),
        )
        .unwrap()
    }

    /// Starts a finite HTTP fixture and returns every observed method, URL, and request body.
    fn spawn_fixture(responses: Vec<(u16, &'static str)>) -> (String, JoinHandle<Vec<String>>) {
        let server = Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = thread::spawn(move || {
            let mut observed = Vec::new();
            for (status, body) in responses {
                let mut request = server.recv().unwrap();
                let mut request_body = String::new();
                request
                    .as_reader()
                    .read_to_string(&mut request_body)
                    .unwrap();
                observed.push(format!(
                    "{} {} {}",
                    request.method(),
                    request.url(),
                    request_body
                ));
                request
                    .respond(TinyResponse::from_string(body).with_status_code(TinyStatus(status)))
                    .unwrap();
            }
            observed
        });
        (base_url, handle)
    }

    /// Verifies exact zone/record filters and typed IPv4 parsing through real HTTP requests.
    #[test]
    fn resolves_zone_and_finds_record_over_http() {
        let (base_url, handle) = spawn_fixture(vec![
            (
                200,
                r#"{"success":true,"errors":[],"result":[{"id":"zone-1","name":"example.com"}]}"#,
            ),
            (
                200,
                r#"{"success":true,"errors":[],"result":[{"id":"record-1","name":"www.example.com","content":"203.0.113.8","type":"A"}]}"#,
            ),
        ]);
        let client = fixture_client(base_url);
        let zone_id = client.resolve_zone_id("example.com").unwrap();
        let record = client
            .find_a_record(&zone_id, "www.example.com")
            .unwrap()
            .unwrap();
        assert_eq!(record.content, Ipv4Addr::new(203, 0, 113, 8));
        let observed = handle.join().unwrap();
        assert!(observed[0].contains("/zones?name=example.com"));
        assert!(observed[1].contains("type=A&name=www.example.com"));
    }

    /// Verifies create/update payloads preserve proxied A records with automatic TTL.
    #[test]
    fn writes_canonical_a_record_payloads() {
        let response = r#"{"success":true,"errors":[],"result":{"id":"record-1","name":"www.example.com","content":"203.0.113.9","type":"A"}}"#;
        let (base_url, handle) = spawn_fixture(vec![(200, response), (200, response)]);
        let client = fixture_client(base_url);
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        client
            .create_a_record("zone-1", "www.example.com", ip)
            .unwrap();
        client
            .update_a_record("zone-1", "record-1", "www.example.com", ip)
            .unwrap();
        let observed = handle.join().unwrap();
        assert!(observed[0].starts_with("POST /zones/zone-1/dns_records"));
        assert!(observed[1].starts_with("PUT /zones/zone-1/dns_records/record-1"));
        assert!(
            observed
                .iter()
                .all(|request| request.contains(r#""proxied":true"#)
                    && request.contains(r#""ttl":1"#))
        );
    }

    /// Verifies a transient server failure is retried while preserving the same operation.
    #[test]
    fn retries_transient_cloudflare_failure() {
        let failure =
            r#"{"success":false,"errors":[{"code":1000,"message":"temporary"}],"result":[]}"#;
        let success =
            r#"{"success":true,"errors":[],"result":[{"id":"zone-1","name":"example.com"}]}"#;
        let (base_url, handle) = spawn_fixture(vec![(500, failure), (200, success)]);
        let client = fixture_client(base_url);
        assert_eq!(client.resolve_zone_id("example.com").unwrap(), "zone-1");
        assert_eq!(handle.join().unwrap().len(), 2);
    }
}
