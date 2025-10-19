use base64::Engine;
use base64::engine::general_purpose;
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspNonce {
    pub(crate) value: String,
}

impl CspNonce {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn header_value(&self) -> String {
        format!("'nonce-{}'", self.value)
    }

    pub fn into_inner(self) -> String {
        self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CspNonceManager {
    byte_len: usize,
}

impl CspNonceManager {
    pub fn new() -> Self {
        Self { byte_len: 32 }
    }

    pub fn with_size(byte_len: usize) -> Result<Self, CspNonceManagerError> {
        if byte_len == 0 {
            return Err(CspNonceManagerError::InvalidLength);
        }

        Ok(Self { byte_len })
    }

    pub fn issue(&self) -> CspNonce {
        let value = generate_nonce_with_size(self.byte_len);
        CspNonce { value }
    }

    pub fn issue_header_value(&self) -> String {
        self.issue().header_value()
    }

    pub fn byte_len(&self) -> usize {
        self.byte_len
    }
}

impl Default for CspNonceManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_nonce() -> String {
    generate_nonce_with_size(32)
}

pub fn generate_nonce_with_size(byte_len: usize) -> String {
    if byte_len == 0 {
        return String::new();
    }

    let mut buffer = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut buffer);
    general_purpose::STANDARD.encode(buffer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CspNonceManagerError {
    #[error("nonce length must be greater than zero")]
    InvalidLength,
}

#[cfg(test)]
#[path = "nonce_test.rs"]
mod nonce_test;
