use std::io::Read;
use std::net::Ipv4Addr;
use std::time::Duration;

use aes::Aes128;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::blocking::{Client, Response};
use reqwest::header::{COOKIE, HeaderMap, HeaderValue, REFERER, SET_COOKIE};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::error::{Result, UpdaterError};
use crate::logging;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const RSA_CHUNK_BYTES: usize = 53;

pub trait WanIpProvider {
    /// Reads and validates the current router WAN IPv4 address.
    fn read_wan_ipv4(&self) -> Result<Ipv4Addr>;
}

pub struct TpLinkClient {
    client: Client,
    host: String,
    password: String,
}

impl TpLinkClient {
    /// Creates a direct LAN client that bypasses host proxy settings and retains strict timeouts.
    pub fn new(host: String, password: String, timeout: Duration) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let referer =
            HeaderValue::from_str(&format!("{host}/webpages/index.html")).map_err(|_| {
                UpdaterError::Config(
                    "TP_LINK_ROUTER_HOST cannot be represented as a Referer header".into(),
                )
            })?;
        headers.insert(REFERER, referer);
        let client = Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .no_proxy()
            .build()
            .map_err(|source| UpdaterError::http("building TP-Link client", source))?;
        Ok(Self {
            client,
            host,
            password,
        })
    }

    /// Establishes the encrypted router session and returns only ephemeral session state.
    fn login(&self) -> Result<RouterSession<'_>> {
        let password_key: KeyResponse = self.read_plain_form("keys")?;
        let auth_key: AuthResponse = self.read_plain_form("auth")?;
        let password_public_key = rsa_public_key(&password_key.password, "password")?;
        let session_public_key = rsa_public_key(&auth_key.key, "session")?;
        let crypto = RouterCrypto::random(session_public_key);
        let encrypted_password = rsa_encrypt(&password_public_key, self.password.as_bytes())?;
        let login_form = format!("operation=login&password={encrypted_password}&confirm=true");
        let credential_hash = format!("{:x}", md5::compute(format!("admin{}", self.password)));
        self.submit_login(auth_key.seq, credential_hash, crypto, login_form)
    }

    /// Reads one public login form used to negotiate router encryption parameters.
    fn read_plain_form<T: for<'de> Deserialize<'de>>(&self, form: &str) -> Result<T> {
        let url = format!("{}/cgi-bin/luci/;stok=/login?form={form}", self.host);
        let response = self
            .client
            .post(url)
            .query(&[("operation", "read")])
            .send()
            .map_err(|source| {
                UpdaterError::http(format!("reading TP-Link {form} parameters"), source)
            })?;
        let bytes = read_bounded(response, &format!("reading TP-Link {form} parameters"))?;
        let envelope: PlainEnvelope<T> = serde_json::from_slice(&bytes).map_err(|source| {
            UpdaterError::serialization(format!("parsing TP-Link {form} parameters"), source)
        })?;
        if envelope.success == Some(false) {
            return Err(UpdaterError::Protocol(format!(
                "TP-Link {form} request was rejected"
            )));
        }
        Ok(envelope.data)
    }

    /// Submits the encrypted login payload and extracts the session token and cookie.
    fn submit_login(
        &self,
        sequence: u64,
        credential_hash: String,
        crypto: RouterCrypto,
        login_form: String,
    ) -> Result<RouterSession<'_>> {
        let (sign, data) = crypto.prepare_payload(&login_form, sequence, &credential_hash, true)?;
        let url = format!("{}/cgi-bin/luci/;stok=/login?form=login", self.host);
        let response = self
            .client
            .post(url)
            .form(&[("sign", sign), ("data", data)])
            .send()
            .map_err(|source| UpdaterError::http("logging into TP-Link router", source))?;
        let cookie = sysauth_cookie(&response)?;
        let bytes = read_bounded(response, "reading TP-Link login response")?;
        let login: PlainEnvelope<LoginResponse> =
            crypto.decrypt_envelope(&bytes, "TP-Link login response")?;
        if login.success == Some(false) || login.data.stok.is_empty() {
            return Err(UpdaterError::Protocol("TP-Link login was rejected".into()));
        }
        Ok(RouterSession {
            owner: self,
            crypto,
            sequence,
            credential_hash,
            stok: login.data.stok,
            cookie,
        })
    }
}

impl WanIpProvider for TpLinkClient {
    /// Logs in, reads WAN status, always attempts logout, and preserves the primary read failure.
    fn read_wan_ipv4(&self) -> Result<Ipv4Addr> {
        let mut session = self.login()?;
        let result = session.read_wan_ipv4();
        if let Err(error) = session.logout() {
            logging::warn(format!("TP-Link logout failed: {error}"));
        }
        result
    }
}

struct RouterSession<'a> {
    owner: &'a TpLinkClient,
    crypto: RouterCrypto,
    sequence: u64,
    credential_hash: String,
    stok: String,
    cookie: String,
}

impl RouterSession<'_> {
    /// Reads and validates the encrypted router IPv4 status payload.
    fn read_wan_ipv4(&self) -> Result<Ipv4Addr> {
        let data: StatusResponse = self.request(
            "admin/network?form=status_ipv4&operation=read",
            "operation=read",
            false,
        )?;
        data.wan_ipv4_ipaddr.parse().map_err(|_| {
            UpdaterError::Protocol("TP-Link router returned an invalid WAN IPv4 address".into())
        })
    }

    /// Logs out the single router session so the router's one-login limit is released promptly.
    fn logout(&mut self) -> Result<()> {
        let _: serde_json::Value =
            self.request("admin/system?form=logout", "operation=write", true)?;
        self.stok.zeroize();
        self.cookie.zeroize();
        Ok(())
    }

    /// Sends one signed encrypted session request and decrypts its typed data block.
    fn request<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        form: &str,
        ignore_body: bool,
    ) -> Result<T> {
        let (sign, data) =
            self.crypto
                .prepare_payload(form, self.sequence, &self.credential_hash, false)?;
        let url = format!(
            "{}/cgi-bin/luci/;stok={}/{}",
            self.owner.host, self.stok, path
        );
        let response = self
            .owner
            .client
            .post(url)
            .header(COOKIE, format!("sysauth={}", self.cookie))
            .form(&[("sign", sign), ("data", data)])
            .send()
            .map_err(|source| UpdaterError::http("calling TP-Link session endpoint", source))?;
        if !response.status().is_success() {
            return Err(UpdaterError::Protocol(format!(
                "TP-Link session endpoint returned HTTP {}",
                response.status()
            )));
        }
        if ignore_body {
            return serde_json::from_value(serde_json::Value::Null).map_err(|source| {
                UpdaterError::serialization("building ignored TP-Link response", source)
            });
        }
        let bytes = read_bounded(response, "reading TP-Link session response")?;
        let envelope: PlainEnvelope<T> = self
            .crypto
            .decrypt_envelope(&bytes, "TP-Link session response")?;
        if envelope.success == Some(false) {
            return Err(UpdaterError::Protocol(
                "TP-Link session request was rejected".into(),
            ));
        }
        Ok(envelope.data)
    }
}

impl Drop for RouterSession<'_> {
    /// Clears derived credentials and session identifiers even when status or logout fails.
    fn drop(&mut self) {
        self.credential_hash.zeroize();
        self.stok.zeroize();
        self.cookie.zeroize();
    }
}

struct RouterCrypto {
    key: [u8; 16],
    iv: [u8; 16],
    public_key: RsaPublicKey,
}

impl RouterCrypto {
    /// Generates the router's required hexadecimal ASCII AES key and IV from OS entropy.
    fn random(public_key: RsaPublicKey) -> Self {
        let mut key_seed = [0_u8; 8];
        let mut iv_seed = [0_u8; 8];
        OsRng.fill_bytes(&mut key_seed);
        OsRng.fill_bytes(&mut iv_seed);
        let mut key = [0_u8; 16];
        let mut iv = [0_u8; 16];
        key.copy_from_slice(hex::encode(key_seed).as_bytes());
        iv.copy_from_slice(hex::encode(iv_seed).as_bytes());
        Self {
            key,
            iv,
            public_key,
        }
    }

    /// Encrypts one form and signs its length/session material using the TP-Link legacy wire protocol.
    fn prepare_payload(
        &self,
        form: &str,
        sequence: u64,
        credential_hash: &str,
        is_login: bool,
    ) -> Result<(String, String)> {
        let data = self.encrypt(form.as_bytes())?;
        let signature_input = if is_login {
            format!(
                "k={}&i={}&h={credential_hash}&s={}",
                String::from_utf8_lossy(&self.key),
                String::from_utf8_lossy(&self.iv),
                sequence + data.len() as u64
            )
        } else {
            format!("h={credential_hash}&s={}", sequence + data.len() as u64)
        };
        let sign = rsa_encrypt_chunks(
            &self.public_key,
            signature_input.as_bytes(),
            RSA_CHUNK_BYTES,
        )?;
        Ok((sign, data))
    }

    /// AES-CBC-encrypts and Base64-encodes a router request body.
    fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let ciphertext = Encryptor::<Aes128>::new(&self.key.into(), &self.iv.into())
            .encrypt_padded_vec::<Pkcs7>(plaintext);
        Ok(BASE64.encode(ciphertext))
    }

    /// Decrypts an encrypted router JSON envelope into the expected typed plaintext envelope.
    fn decrypt_envelope<T: for<'de> Deserialize<'de>>(
        &self,
        bytes: &[u8],
        context: &str,
    ) -> Result<T> {
        let encrypted: EncryptedEnvelope = serde_json::from_slice(bytes)
            .map_err(|source| UpdaterError::serialization(context, source))?;
        let ciphertext = BASE64
            .decode(encrypted.data)
            .map_err(|_| UpdaterError::Protocol(format!("{context} contained invalid Base64")))?;
        let plaintext = Decryptor::<Aes128>::new(&self.key.into(), &self.iv.into())
            .decrypt_padded_vec::<Pkcs7>(&ciphertext)
            .map_err(|_| UpdaterError::Protocol(format!("{context} could not be decrypted")))?;
        serde_json::from_slice(&plaintext)
            .map_err(|source| UpdaterError::serialization(context, source))
    }
}

impl Drop for RouterCrypto {
    /// Clears ephemeral symmetric session material before releasing its allocation.
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

#[derive(Deserialize)]
struct PlainEnvelope<T> {
    data: T,
    success: Option<bool>,
}

#[derive(Deserialize)]
struct EncryptedEnvelope {
    data: String,
}

#[derive(Deserialize)]
struct KeyResponse {
    password: Vec<String>,
}

#[derive(Deserialize)]
struct AuthResponse {
    key: Vec<String>,
    seq: u64,
}

#[derive(Deserialize)]
struct LoginResponse {
    stok: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    wan_ipv4_ipaddr: String,
}

/// Converts the router's modulus/exponent hex tuple into a validated RSA public key.
fn rsa_public_key(parts: &[String], label: &str) -> Result<RsaPublicKey> {
    if parts.len() != 2 {
        return Err(UpdaterError::Protocol(format!(
            "TP-Link {label} RSA key was malformed"
        )));
    }
    let modulus = BigUint::parse_bytes(parts[0].as_bytes(), 16).ok_or_else(|| {
        UpdaterError::Protocol(format!("TP-Link {label} RSA modulus was invalid"))
    })?;
    let exponent = BigUint::parse_bytes(parts[1].as_bytes(), 16).ok_or_else(|| {
        UpdaterError::Protocol(format!("TP-Link {label} RSA exponent was invalid"))
    })?;
    RsaPublicKey::new(modulus, exponent)
        .map_err(|_| UpdaterError::Protocol(format!("TP-Link {label} RSA key was invalid")))
}

/// Encrypts one PKCS#1 v1.5 chunk and returns the router's lowercase hexadecimal representation.
fn rsa_encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<String> {
    public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext)
        .map(hex::encode)
        .map_err(|_| UpdaterError::Protocol("TP-Link RSA encryption failed".into()))
}

/// Encrypts fixed-size protocol chunks and concatenates their hexadecimal ciphertext blocks.
fn rsa_encrypt_chunks(
    public_key: &RsaPublicKey,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<String> {
    let mut encrypted = String::new();
    for chunk in plaintext.chunks(chunk_size) {
        encrypted.push_str(&rsa_encrypt(public_key, chunk)?);
    }
    Ok(encrypted)
}

/// Extracts the router session cookie without retaining unrelated cookie attributes.
fn sysauth_cookie(response: &Response) -> Result<String> {
    for value in response.headers().get_all(SET_COOKIE) {
        if let Ok(text) = value.to_str()
            && let Some(cookie) = text
                .split(';')
                .find_map(|part| part.trim().strip_prefix("sysauth="))
        {
            return Ok(cookie.to_owned());
        }
    }
    Err(UpdaterError::Protocol(
        "TP-Link login response did not set sysauth".into(),
    ))
}

/// Reads a bounded router response so a compromised LAN endpoint cannot exhaust process memory.
fn read_bounded(mut response: Response, context: &str) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(UpdaterError::Protocol(format!(
            "{context} returned HTTP {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| UpdaterError::Io {
            context: context.into(),
            source,
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(UpdaterError::Protocol(format!(
            "{context} returned an oversized response"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;

    use super::*;

    /// Builds deterministic session crypto for round-trip tests without network access.
    fn fixture_crypto() -> RouterCrypto {
        let private = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        RouterCrypto {
            key: *b"0123456789abcdef",
            iv: *b"fedcba9876543210",
            public_key: private.to_public_key(),
        }
    }

    /// Verifies the router AES format round-trips through the real envelope decoder.
    #[test]
    fn encrypts_and_decrypts_router_envelope() {
        let crypto = fixture_crypto();
        let plaintext = br#"{"data":{"wan_ipv4_ipaddr":"203.0.113.7"},"success":true}"#;
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let outer = serde_json::to_vec(&serde_json::json!({"data": encrypted})).unwrap();
        let decoded: PlainEnvelope<StatusResponse> =
            crypto.decrypt_envelope(&outer, "fixture").unwrap();
        assert_eq!(decoded.data.wan_ipv4_ipaddr, "203.0.113.7");
    }

    /// Verifies login signatures include multiple fixed-width RSA ciphertext blocks when required.
    #[test]
    fn signs_router_payload_in_protocol_chunks() {
        let crypto = fixture_crypto();
        let (sign, data) = crypto
            .prepare_payload(
                "operation=read",
                42,
                "0123456789abcdef0123456789abcdef",
                true,
            )
            .unwrap();
        assert!(!data.is_empty());
        assert_eq!(sign.len() % 256, 0);
        assert!(sign.len() >= 512);
    }
}
