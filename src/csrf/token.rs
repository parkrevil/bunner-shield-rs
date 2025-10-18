use core::sync::atomic::{AtomicU64, Ordering};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacCsrfService {
    secret: [u8; 32],
    counter: AtomicU64,
}

impl HmacCsrfService {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            counter: AtomicU64::new(0),
        }
    }

    pub fn issue(&self, length: usize) -> Result<String, CsrfTokenError> {
        if length == 0 || length > 64 {
            return Err(CsrfTokenError::InvalidTokenLength(length));
        }

        let nonce = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let computed = self.compute_token(nonce)?;
        let encoded = Self::encode_hex(&computed);

        Ok(encoded[..length].to_string())
    }

    fn compute_token(&self, nonce: u64) -> Result<[u8; 32], CsrfTokenError> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| CsrfTokenError::InvalidSecretLength)?;
        mac.update(&nonce.to_be_bytes());

        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);

        for &byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }

        output
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CsrfTokenError {
    #[error("invalid secret length for HMAC")]
    InvalidSecretLength,
    #[error("token length {0} exceeds allowable range")]
    InvalidTokenLength(usize),
}

#[cfg(test)]
#[path = "token_test.rs"]
mod token_test;
