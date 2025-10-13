use crate::executor::FeatureOptions;
use thiserror::Error;

const PRELOAD_MIN_MAX_AGE: u64 = 31_536_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsOptions {
    pub(crate) max_age: u64,
    pub(crate) include_subdomains: bool,
    pub(crate) preload: bool,
}

impl HstsOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = seconds;
        self
    }

    pub fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    pub fn preload(mut self) -> Self {
        self.preload = true;
        self
    }

    pub fn header_value(&self) -> String {
        let mut parts = vec![format!("max-age={}", self.max_age)];

        if self.include_subdomains {
            parts.push("includeSubDomains".to_string());
        }

        if self.preload {
            parts.push("preload".to_string());
        }

        parts.join("; ")
    }
}

impl Default for HstsOptions {
    fn default() -> Self {
        Self {
            max_age: PRELOAD_MIN_MAX_AGE,
            include_subdomains: false,
            preload: false,
        }
    }
}

impl FeatureOptions for HstsOptions {
    type Error = HstsOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.max_age == 0 {
            return Err(HstsOptionsError::InvalidMaxAge);
        }

        if self.preload && !self.include_subdomains {
            return Err(HstsOptionsError::PreloadRequiresIncludeSubdomains);
        }

        if self.preload && self.max_age < PRELOAD_MIN_MAX_AGE {
            return Err(HstsOptionsError::PreloadRequiresLongMaxAge);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HstsOptionsError {
    #[error("max-age must be greater than zero")]
    InvalidMaxAge,
    #[error("preload requires includeSubDomains to be enabled")]
    PreloadRequiresIncludeSubdomains,
    #[error("preload requires max-age of at least 31536000 seconds")]
    PreloadRequiresLongMaxAge,
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
