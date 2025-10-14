use super::CspOptions;
use crate::constants::header_keys::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO, REPORTING_ENDPOINTS,
};
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct Csp {
    options: CspOptions,
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Csp {
    type Options = CspOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let header_name = if self.options.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        headers.insert(header_name, self.options.header_value());

        if let Some(group) = &self.options.report_group {
            headers.insert(REPORT_TO, group.header_value());
        }

        if !self.options.reporting_endpoints.is_empty() {
            let value = self
                .options
                .reporting_endpoints
                .iter()
                .map(|endpoint| endpoint.header_fragment())
                .collect::<Vec<_>>()
                .join(", ");
            headers.insert(REPORTING_ENDPOINTS, value);
        }

        Ok(())
    }
}
