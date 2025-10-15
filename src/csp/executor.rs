use super::CspOptions;
use crate::constants::header_keys::CONTENT_SECURITY_POLICY;
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
        headers.insert(CONTENT_SECURITY_POLICY, self.options.header_value());

        Ok(())
    }
}
