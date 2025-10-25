use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions};
use crate::normalized_headers::NormalizedHeaders;

pub(crate) struct SafeHeaders {
    options: NoopOptions,
}

impl SafeHeaders {
    pub(crate) fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl FeatureExecutor for SafeHeaders {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.sanitize_for_http();
        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
