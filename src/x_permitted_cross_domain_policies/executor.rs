use super::XPermittedCrossDomainPoliciesOptions;
use crate::constants::header_keys::X_PERMITTED_CROSS_DOMAIN_POLICIES;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
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

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(X_PERMITTED_CROSS_DOMAIN_POLICIES) {
            context.push_runtime_info(
                "x-permitted-cross-domain-policies",
                format!("Emitted X-Permitted-Cross-Domain-Policies header: {value}"),
            );
        }

        Ok(())
    }
}
