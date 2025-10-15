use super::HstsOptions;
use crate::constants::header_keys::STRICT_TRANSPORT_SECURITY;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct Hsts {
    options: HstsOptions,
}

impl Hsts {
    pub fn new(options: HstsOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Hsts {
    type Options = HstsOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(STRICT_TRANSPORT_SECURITY, self.options.header_value());

        Ok(())
    }
}
