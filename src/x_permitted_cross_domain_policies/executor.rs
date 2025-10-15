use super::XPermittedCrossDomainPoliciesOptions;
use crate::constants::header_keys::X_PERMITTED_CROSS_DOMAIN_POLICIES;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct XPermittedCrossDomainPolicies {
    options: XPermittedCrossDomainPoliciesOptions,
}

impl XPermittedCrossDomainPolicies {
    pub fn new(options: XPermittedCrossDomainPoliciesOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for XPermittedCrossDomainPolicies {
    type Options = XPermittedCrossDomainPoliciesOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(
            X_PERMITTED_CROSS_DOMAIN_POLICIES,
            self.options.header_value(),
        );

        Ok(())
    }
}
