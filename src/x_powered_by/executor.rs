use crate::constants::header_keys::X_POWERED_BY;
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

    fn validate_options(&self) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.remove(X_POWERED_BY);

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
