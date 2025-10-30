use crate::constants::header_values::{
    COOP_SAME_ORIGIN, COOP_SAME_ORIGIN_ALLOW_POPUPS, COOP_UNSAFE_NONE,
};
use crate::executor::{FeatureOptions, PolicyMode};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoopPolicy {
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone,
}

impl CoopPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoopPolicy::SameOrigin => COOP_SAME_ORIGIN,
            CoopPolicy::SameOriginAllowPopups => COOP_SAME_ORIGIN_ALLOW_POPUPS,
            CoopPolicy::UnsafeNone => COOP_UNSAFE_NONE,
        }
    }
}

impl FromStr for CoopPolicy {
    type Err = CoopOptionsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim();

        match normalized.to_ascii_lowercase().as_str() {
            "same-origin" => Ok(CoopPolicy::SameOrigin),
            "same-origin-allow-popups" => Ok(CoopPolicy::SameOriginAllowPopups),
            "unsafe-none" => Ok(CoopPolicy::UnsafeNone),
            _ => Err(CoopOptionsError::InvalidPolicy(normalized.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoopOptions {
    pub(crate) policy: CoopPolicy,
    pub(crate) mode: PolicyMode,
}

impl CoopOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CoopPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy_from_str(mut self, policy: &str) -> Result<Self, CoopOptionsError> {
        self.policy = policy.parse()?;
        Ok(self)
    }

    pub fn from_policy_str(policy: &str) -> Result<Self, CoopOptionsError> {
        Ok(Self {
            policy: policy.parse()?,
            mode: PolicyMode::Enforce,
        })
    }

    pub fn report_only(mut self) -> Self {
        self.mode = PolicyMode::ReportOnly;
        self
    }

    pub fn mode(&self) -> PolicyMode {
        self.mode
    }
}

impl Default for CoopOptions {
    fn default() -> Self {
        Self {
            policy: CoopPolicy::SameOrigin,
            mode: PolicyMode::Enforce,
        }
    }
}

impl FeatureOptions for CoopOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoopOptionsError {
    #[error(
        "cross-origin-opener-policy must be one of: same-origin, same-origin-allow-popups, unsafe-none (got `{0}`)"
    )]
    InvalidPolicy(String),
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
