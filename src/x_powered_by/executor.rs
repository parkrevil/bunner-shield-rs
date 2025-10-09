use crate::constants::headers::X_POWERED_BY;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions};
use crate::normalized_headers::NormalizedHeaders;

pub struct XPoweredBy {
    options: NoopOptions,
}

impl XPoweredBy {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl FeatureExecutor for XPoweredBy {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.remove(X_POWERED_BY);

        Ok(())
    }
}
