use crate::constants::cookie::COOKIE_PREFIX_SECURE;
use crate::executor::{FeatureOptions, ReportContext};
use thiserror::Error;

const DEFAULT_COOKIE_NAME: &str = "__Host-csrf-token";
const DEFAULT_TOKEN_LENGTH: usize = 64;
const MIN_TOKEN_LENGTH: usize = 32;
const MAX_TOKEN_LENGTH: usize = 64;

pub struct CsrfOptions {
    pub(crate) cookie_name: String,
    pub(crate) token_length: usize,
    pub(crate) secret_key: [u8; 32],
}

impl CsrfOptions {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            token_length: DEFAULT_TOKEN_LENGTH,
            secret_key,
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

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "csrf",
            format!(
                "Configured CSRF cookie `{}` with token length {}",
                self.cookie_name, self.token_length
            ),
        );
    }
}

#[derive(Debug, Error)]
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
