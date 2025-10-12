use crate::constants::header_values::{COEP_CREDENTIALLESS, COEP_REQUIRE_CORP};
use crate::executor::FeatureOptions;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoepPolicy {
    RequireCorp,
    Credentialless,
}

impl CoepPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoepPolicy::RequireCorp => COEP_REQUIRE_CORP,
            CoepPolicy::Credentialless => COEP_CREDENTIALLESS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoepOptions {
    pub(crate) policy: CoepPolicy,
    pub(crate) cache_warning: bool,
}

impl CoepOptions {
    pub fn new() -> Self {
        Self {
            policy: CoepPolicy::RequireCorp,
            cache_warning: false,
        }
    }

    pub fn policy(mut self, policy: CoepPolicy) -> Self {
        self.policy = policy;
        if matches!(self.policy, CoepPolicy::Credentialless) {
            self.cache_warning = true;
        }
        self
    }

    pub fn cache_warning(mut self, enabled: bool) -> Self {
        self.cache_warning = enabled;
        self
    }
}

impl Default for CoepOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureOptions for CoepOptions {
    type Error = CoepOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if matches!(self.policy, CoepPolicy::Credentialless) && !self.cache_warning {
            return Err(CoepOptionsError::CredentiallessRequiresWarning);
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoepOptionsError {
    #[error("credentialless mode must include cache impact warning")]
    CredentiallessRequiresWarning,
}
