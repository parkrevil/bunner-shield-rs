use crate::executor::{FeatureOptions, ReportContext};
use std::error::Error;
use std::fmt;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionsPolicyOptionsError {
    EmptyPolicy,
}

impl fmt::Display for PermissionsPolicyOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionsPolicyOptionsError::EmptyPolicy => {
                f.write_str("permissions policy value must not be empty")
            }
        }
    }
}

impl Error for PermissionsPolicyOptionsError {}

impl FeatureOptions for PermissionsPolicyOptions {
    type Error = PermissionsPolicyOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.policy.trim().is_empty() {
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        } else {
            Ok(())
        }
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "permissions-policy",
            format!("Configured Permissions-Policy: {}", self.policy.trim()),
        );
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
