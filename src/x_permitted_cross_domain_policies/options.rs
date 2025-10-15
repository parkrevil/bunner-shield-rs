use crate::constants::header_values::{
    X_PERMITTED_CROSS_DOMAIN_POLICIES_ALL, X_PERMITTED_CROSS_DOMAIN_POLICIES_BY_CONTENT_TYPE,
    X_PERMITTED_CROSS_DOMAIN_POLICIES_MASTER_ONLY, X_PERMITTED_CROSS_DOMAIN_POLICIES_NONE,
};
use crate::executor::{FeatureOptions, ReportContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XPermittedCrossDomainPoliciesPolicy {
    None,
    MasterOnly,
    ByContentType,
    All,
}

impl XPermittedCrossDomainPoliciesPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            XPermittedCrossDomainPoliciesPolicy::None => X_PERMITTED_CROSS_DOMAIN_POLICIES_NONE,
            XPermittedCrossDomainPoliciesPolicy::MasterOnly => {
                X_PERMITTED_CROSS_DOMAIN_POLICIES_MASTER_ONLY
            }
            XPermittedCrossDomainPoliciesPolicy::ByContentType => {
                X_PERMITTED_CROSS_DOMAIN_POLICIES_BY_CONTENT_TYPE
            }
            XPermittedCrossDomainPoliciesPolicy::All => X_PERMITTED_CROSS_DOMAIN_POLICIES_ALL,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XPermittedCrossDomainPoliciesOptions {
    policy: XPermittedCrossDomainPoliciesPolicy,
}

impl XPermittedCrossDomainPoliciesOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: XPermittedCrossDomainPoliciesPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn header_value(&self) -> &'static str {
        self.policy.as_str()
    }
}

impl Default for XPermittedCrossDomainPoliciesOptions {
    fn default() -> Self {
        Self {
            policy: XPermittedCrossDomainPoliciesPolicy::None,
        }
    }
}

impl FeatureOptions for XPermittedCrossDomainPoliciesOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "x-permitted-cross-domain-policies",
            format!(
                "Configured X-Permitted-Cross-Domain-Policies: {}",
                self.policy.as_str()
            ),
        );
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
