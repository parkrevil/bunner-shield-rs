use crate::executor::FeatureOptions;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsPolicyOptions {
    policy: String,
}

impl PermissionsPolicyOptions {
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
        }
    }

    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = policy.into();
        self
    }

    pub(crate) fn header_value(&self) -> &str {
        self.policy.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionsPolicyOptionsError {
    #[error("permissions policy value must not be empty")]
    EmptyPolicy,
}

impl FeatureOptions for PermissionsPolicyOptions {
    type Error = PermissionsPolicyOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.policy.trim().is_empty() {
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
