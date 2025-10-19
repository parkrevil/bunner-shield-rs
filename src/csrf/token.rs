use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core::sync::atomic::{AtomicU64, Ordering};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_VERSION_V1: u8 = 1; // legacy: [v1][nonce(8)][mac]
const TOKEN_VERSION_V2: u8 = 2; // current: [v2][ts(8)][nonce(8)][mac]

pub struct HmacCsrfService {
    secret: [u8; 32],
    /// Additional keys accepted during verification. The first key is always `secret`.
    verification_keys: Vec<[u8; 32]>,
    pub(crate) counter: AtomicU64,
}

impl HmacCsrfService {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            verification_keys: Vec::new(),
            counter: AtomicU64::new(0),
        }
    }

    /// Creates a service that issues tokens with `secret` and verifies against
    /// `secret` plus any additional `verification_keys`.
    pub fn with_verification_keys(secret: [u8; 32], verification_keys: Vec<[u8; 32]>) -> Self {
        Self {
            secret,
            verification_keys,
            counter: AtomicU64::new(0),
        }
    }

    /// Issues a CSRF token.
    ///
    /// Token format (base64url without padding):
    /// [version(1)][ts(8)][nonce(8)][mac_trunc(n)] for v2 tokens
    /// where mac = HMAC(secret, ts_be || nonce_be).
    /// The `length` parameter controls the truncated MAC length in hex-equivalent
    /// semantics from previous versions (32..=64 hex chars -> 16..=32 bytes).
    pub fn issue(&self, length: usize) -> Result<String, CsrfTokenError> {
        if length == 0 || length > 64 {
            return Err(CsrfTokenError::InvalidTokenLength(length));
        }

        // Historically `length` was hex chars, two chars per byte.
        // Keep the effective MAC truncation security equivalent.
        let mac_len = length
            .checked_div(2)
            .ok_or(CsrfTokenError::InvalidTokenLength(length))?;
        if mac_len == 0 {
            return Err(CsrfTokenError::InvalidTokenLength(length));
        }
        if mac_len > 32 {
            return Err(CsrfTokenError::InvalidTokenLength(length));
        }

        let nonce = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CsrfTokenError::InvalidTimestamp)?
            .as_secs();
        let mut msg = [0u8; 16];
        msg[..8].copy_from_slice(&now.to_be_bytes());
        msg[8..].copy_from_slice(&nonce.to_be_bytes());

        let mac_full = self.compute_mac_bytes_with_secret(&self.secret, &msg)?;
        let mac_trunc = &mac_full[..mac_len];

        let mut raw = Vec::with_capacity(1 + 8 + 8 + mac_len);
        raw.push(TOKEN_VERSION_V2);
        raw.extend_from_slice(&now.to_be_bytes());
        raw.extend_from_slice(&nonce.to_be_bytes());
        raw.extend_from_slice(mac_trunc);

        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Verifies a CSRF token (signature only; no expiry or replay checks here).
    pub fn verify(&self, token: &str) -> Result<(), CsrfTokenError> {
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CsrfTokenError::InvalidEncoding)?;

        if raw.is_empty() {
            return Err(CsrfTokenError::InvalidStructure);
        }

        let version = raw[0];
        match version {
            TOKEN_VERSION_V1 => {
                if raw.len() < 1 + 8 + 16 {
                    return Err(CsrfTokenError::InvalidStructure);
                }
                let mut nonce_bytes = [0u8; 8];
                nonce_bytes.copy_from_slice(&raw[1..9]);
                let nonce = u64::from_be_bytes(nonce_bytes);
                let mac_provided = &raw[9..];

                if self.mac_matches_any(&nonce.to_be_bytes(), mac_provided)? {
                    Ok(())
                } else {
                    Err(CsrfTokenError::InvalidSignature)
                }
            }
            TOKEN_VERSION_V2 => {
                if raw.len() < 1 + 8 + 8 + 16 {
                    return Err(CsrfTokenError::InvalidStructure);
                }
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&raw[1..9]);
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&raw[9..17]);
                let mac_provided = &raw[17..];

                let mut msg = [0u8; 16];
                msg[..8].copy_from_slice(&ts);
                msg[8..].copy_from_slice(&nonce);

                if self.mac_matches_any(&msg, mac_provided)? {
                    Ok(())
                } else {
                    Err(CsrfTokenError::InvalidSignature)
                }
            }
            other => Err(CsrfTokenError::UnsupportedVersion(other)),
        }
    }

    /// Verifies a CSRF token with an expiry window (in seconds) using the provided current time.
    /// Only applies to v2 tokens containing a timestamp. v1 tokens return MissingTimestamp.
    pub fn verify_with_max_age(
        &self,
        token: &str,
        max_age_secs: u64,
        now_secs: u64,
    ) -> Result<(), CsrfTokenError> {
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CsrfTokenError::InvalidEncoding)?;
        if raw.is_empty() {
            return Err(CsrfTokenError::InvalidStructure);
        }
        if max_age_secs == 0 {
            return Err(CsrfTokenError::InvalidMaxAge(0));
        }
        match raw[0] {
            TOKEN_VERSION_V1 => Err(CsrfTokenError::MissingTimestamp),
            TOKEN_VERSION_V2 => {
                if raw.len() < 1 + 8 + 8 + 16 {
                    return Err(CsrfTokenError::InvalidStructure);
                }
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&raw[1..9]);
                let issued_secs = u64::from_be_bytes(ts);
                // replay signature validation
                self.verify(token)?;
                if now_secs
                    .checked_sub(issued_secs)
                    .map(|age| age <= max_age_secs)
                    .unwrap_or(false)
                {
                    Ok(())
                } else {
                    Err(CsrfTokenError::Expired)
                }
            }
            other => Err(CsrfTokenError::UnsupportedVersion(other)),
        }
    }

    /// Verifies a v2 CSRF token and atomically consumes it using the provided replay store.
    /// Returns Replayed if the token has already been seen.
    pub fn verify_and_consume(
        &self,
        token: &str,
        store: &dyn CsrfReplayStore,
    ) -> Result<(), CsrfTokenError> {
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CsrfTokenError::InvalidEncoding)?;
        if raw.is_empty() {
            return Err(CsrfTokenError::InvalidStructure);
        }
        match raw[0] {
            TOKEN_VERSION_V1 => Err(CsrfTokenError::MissingTimestamp),
            TOKEN_VERSION_V2 => {
                if raw.len() < 1 + 8 + 8 + 16 {
                    return Err(CsrfTokenError::InvalidStructure);
                }
                // Validate signature first
                self.verify(token)?;
                // Build unique id = ts||nonce
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&raw[1..9]);
                id[8..].copy_from_slice(&raw[9..17]);
                if store.consume_if_fresh(&id) {
                    Ok(())
                } else {
                    Err(CsrfTokenError::Replayed)
                }
            }
            other => Err(CsrfTokenError::UnsupportedVersion(other)),
        }
    }

    fn compute_mac_bytes_with_secret(
        &self,
        secret: &[u8; 32],
        msg: &[u8],
    ) -> Result<[u8; 32], CsrfTokenError> {
        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| CsrfTokenError::InvalidSecretLength)?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }

    fn mac_matches_any(&self, msg: &[u8], mac_provided: &[u8]) -> Result<bool, CsrfTokenError> {
        // Try primary first
        {
            let mac_full = self.compute_mac_bytes_with_secret(&self.secret, msg)?;
            let mac_expected = &mac_full[..mac_provided.len()];
            if ct_eq(mac_expected, mac_provided) {
                return Ok(true);
            }
        }
        // Try additional keys
        for key in &self.verification_keys {
            let mac_full = self.compute_mac_bytes_with_secret(key, msg)?;
            let mac_expected = &mac_full[..mac_provided.len()];
            if ct_eq(mac_expected, mac_provided) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CsrfTokenError {
    #[error("invalid secret length for HMAC")]
    InvalidSecretLength,
    #[error("token length {0} exceeds allowable range")]
    InvalidTokenLength(usize),
    #[error("invalid base64url encoding for token")]
    InvalidEncoding,
    #[error("invalid token structure")]
    InvalidStructure,
    #[error("unsupported token version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid token signature")]
    InvalidSignature,
    #[error("invalid or negative timestamp")]
    InvalidTimestamp,
    #[error("token missing timestamp for expiry validation")]
    MissingTimestamp,
    #[error("token has expired")]
    Expired,
    #[error("invalid max age {0}")]
    InvalidMaxAge(u64),
    #[error("token has already been used (replay detected)")]
    Replayed,
}

/// A store used to prevent CSRF token replay by tracking seen tokens.
pub trait CsrfReplayStore: Send + Sync {
    /// Returns true if the id was not previously seen and is now recorded.
    /// Returns false if the id was already present (replay).
    fn consume_if_fresh(&self, id: &[u8]) -> bool;
}

/// An in-memory replay store for testing and simple use-cases.
#[allow(dead_code)]
pub struct InMemoryReplayStore {
    seen: Mutex<HashSet<[u8; 16]>>,
}

#[allow(dead_code)]
impl InMemoryReplayStore {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrfReplayStore for InMemoryReplayStore {
    fn consume_if_fresh(&self, id: &[u8]) -> bool {
        if id.len() != 16 {
            return false;
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&id[..16]);
        let mut guard = self.seen.lock().expect("poisoned");
        guard.insert(key)
    }
}

#[cfg(test)]
#[path = "token_test.rs"]
mod token_test;
