use super::CspOptions;
use crate::constants::headers::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO,
};
use crate::executor::FeatureExecutor;
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

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String> {
        let header_name = if self.options.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        headers.insert(header_name, self.options.serialize());

        if let Some(group) = &self.options.report_group {
            headers.insert(REPORT_TO, group.to_header_value());
        }

        Ok(())
    }
}
