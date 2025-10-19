use crate::constants::cookie::COOKIE_PREFIX_SECURE;
use crate::executor::FeatureOptions;
use thiserror::Error;

const DEFAULT_COOKIE_NAME: &str = "__Host-csrf-token";
const DEFAULT_TOKEN_LENGTH: usize = 64;
const MIN_TOKEN_LENGTH: usize = 32;
const MAX_TOKEN_LENGTH: usize = 64;

pub struct CsrfOptions {
    pub(crate) cookie_name: String,
    pub(crate) token_length: usize,
    pub(crate) secret_key: [u8; 32],
    // Additional keys accepted for verification to support key rotation.
    pub(crate) verification_keys: Vec<[u8; 32]>,
    pub(crate) origin_validation: bool,
    pub(crate) use_referer: bool,
}

impl CsrfOptions {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            token_length: DEFAULT_TOKEN_LENGTH,
            secret_key,
            verification_keys: Vec::new(),
            origin_validation: false,
            use_referer: true,
        }
    }

    pub fn cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
        self.cookie_name = cookie_name.into();
        self
    }

    pub fn token_length(mut self, length: usize) -> Self {
        self.token_length = length;
        self
    }

    pub fn origin_validation(mut self, enabled: bool, use_referer: bool) -> Self {
        self.origin_validation = enabled;
        self.use_referer = use_referer;
        self
    }

    /// Configures additional keys that will be accepted during verification.
    /// Issued tokens always use the primary `secret_key`.
    pub fn verification_keys(mut self, keys: Vec<[u8; 32]>) -> Self {
        self.verification_keys = keys;
        self
    }
}

impl FeatureOptions for CsrfOptions {
    type Error = CsrfOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if !self.cookie_name.starts_with(COOKIE_PREFIX_SECURE) {
            return Err(CsrfOptionsError::InvalidCookiePrefix);
        }

        if self.token_length < MIN_TOKEN_LENGTH || self.token_length > MAX_TOKEN_LENGTH {
            return Err(CsrfOptionsError::InvalidTokenLength {
                requested: self.token_length,
                minimum: MIN_TOKEN_LENGTH,
                maximum: MAX_TOKEN_LENGTH,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CsrfOptionsError {
    #[error("csrf cookie must start with secure prefix")]
    InvalidCookiePrefix,
    #[error("csrf token length {requested} is outside of allowed range {minimum}..={maximum}")]
    InvalidTokenLength {
        requested: usize,
        minimum: usize,
        maximum: usize,
    },
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
