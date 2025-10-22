use crate::constants::header_values::{CORP_CROSS_ORIGIN, CORP_SAME_ORIGIN, CORP_SAME_SITE};
use crate::executor::FeatureOptions;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpPolicy {
    SameOrigin,
    SameSite,
    CrossOrigin,
}

impl CorpPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CorpPolicy::SameOrigin => CORP_SAME_ORIGIN,
            CorpPolicy::SameSite => CORP_SAME_SITE,
            CorpPolicy::CrossOrigin => CORP_CROSS_ORIGIN,
        }
    }
}

impl FromStr for CorpPolicy {
    type Err = CorpOptionsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim();

        match normalized.to_ascii_lowercase().as_str() {
            "same-origin" => Ok(CorpPolicy::SameOrigin),
            "same-site" => Ok(CorpPolicy::SameSite),
            "cross-origin" => Ok(CorpPolicy::CrossOrigin),
            _ => Err(CorpOptionsError::InvalidPolicy(normalized.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpOptions {
    pub(crate) policy: CorpPolicy,
}

impl CorpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CorpPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy_from_str(mut self, policy: &str) -> Result<Self, CorpOptionsError> {
        self.policy = policy.parse()?;
        Ok(self)
    }

    pub fn from_policy_str(policy: &str) -> Result<Self, CorpOptionsError> {
        Ok(Self {
            policy: policy.parse()?,
        })
    }
}

impl Default for CorpOptions {
    fn default() -> Self {
        Self {
            policy: CorpPolicy::SameOrigin,
        }
    }
}

impl FeatureOptions for CorpOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CorpOptionsError {
    #[error(
        "cross-origin-resource-policy must be one of: same-origin, same-site, cross-origin (got `{0}`)"
    )]
    InvalidPolicy(String),
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
