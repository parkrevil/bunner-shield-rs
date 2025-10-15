use crate::constants::header_keys::X_CONTENT_TYPE_OPTIONS;
use crate::constants::header_values::NOSNIFF;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions};
use crate::normalized_headers::NormalizedHeaders;

pub struct XContentTypeOptions {
    options: NoopOptions,
}

impl XContentTypeOptions {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl FeatureExecutor for XContentTypeOptions {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);

        Ok(())
    }
}
