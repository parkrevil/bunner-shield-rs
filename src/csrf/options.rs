use crate::constants::cookie::COOKIE_PREFIX_SECURE;
use crate::executor::FeatureOptions;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_COOKIE_NAME: &str = "__Host-csrf-token";
const DEFAULT_TOKEN_LENGTH: usize = 64;
const MIN_TOKEN_LENGTH: usize = 32;
const MAX_TOKEN_LENGTH: usize = 64;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CsrfOptions {
    pub(crate) cookie_name: String,
    pub(crate) token_length: usize,
    pub(crate) secret_key: [u8; 32],
    // Additional keys accepted for verification to support key rotation.
    pub(crate) verification_keys: Vec<[u8; 32]>,
    pub(crate) origin_validation: bool,
    pub(crate) use_referer: bool,
    pub(crate) validate_methods: Vec<String>,
    pub(crate) token_max_age_secs: u64,
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
            validate_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
            ],
            token_max_age_secs: 2 * 60 * 60,
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

    /// Sets which HTTP methods should trigger CSRF token verification when present in request headers.
    /// Values are matched case-insensitively; defaults to [POST, PUT, PATCH, DELETE].
    pub fn validate_methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.validate_methods = methods.into_iter().map(|m| m.into()).collect();
        self
    }

    /// Sets the maximum allowed age for CSRF tokens (seconds) when verifying.
    /// Defaults to 2 hours.
    pub fn token_max_age_secs(mut self, secs: u64) -> Self {
        self.token_max_age_secs = secs;
        self
    }
}

impl FeatureOptions for CsrfOptions {
    type Error = CsrfOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if !self.cookie_name.starts_with(COOKIE_PREFIX_SECURE) {
            return Err(CsrfOptionsError::InvalidCookiePrefix {
                provided: self.cookie_name.clone(),
                required_prefix: COOKIE_PREFIX_SECURE,
            });
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
    #[error("CSRF cookie name `{provided}` must start with `{required_prefix}`")]
    InvalidCookiePrefix {
        provided: String,
        required_prefix: &'static str,
    },
    #[error("CSRF token length {requested} is outside of allowed range {minimum}..={maximum}")]
    InvalidTokenLength {
        requested: usize,
        minimum: usize,
        maximum: usize,
    },
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
