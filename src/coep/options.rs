use crate::constants::header_values::{COEP_CREDENTIALLESS, COEP_REQUIRE_CORP};
use crate::executor::FeatureOptions;
use std::str::FromStr;
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

impl FromStr for CoepPolicy {
    type Err = CoepOptionsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim();

        match normalized.to_ascii_lowercase().as_str() {
            "require-corp" => Ok(CoepPolicy::RequireCorp),
            "credentialless" => Ok(CoepPolicy::Credentialless),
            _ => Err(CoepOptionsError::InvalidPolicy(normalized.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoepOptions {
    pub(crate) policy: CoepPolicy,
}

impl CoepOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CoepPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy_from_str(mut self, policy: &str) -> Result<Self, CoepOptionsError> {
        self.policy = policy.parse()?;
        Ok(self)
    }

    pub fn from_policy_str(policy: &str) -> Result<Self, CoepOptionsError> {
        Ok(Self {
            policy: policy.parse()?,
        })
    }
}

impl Default for CoepOptions {
    fn default() -> Self {
        Self {
            policy: CoepPolicy::RequireCorp,
        }
    }
}

impl FeatureOptions for CoepOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoepOptionsError {
    #[error("cross-origin-embedder-policy must be one of: require-corp, credentialless (got `{0}`)")]
    InvalidPolicy(String),
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
