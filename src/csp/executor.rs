use super::CspOptions;
use crate::constants::header::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO,
};
use crate::executor::Executor;
use crate::normalized_headers::NormalizedHeaders;

pub struct Csp {
    options: CspOptions,
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        Self { options }
    }
}

impl Executor for Csp {
    fn validate_options(&self) -> Result<(), String> {
        self.options
            .clone()
            .validate()
            .map(|_| ())
            .map_err(|err| err.to_string())
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
