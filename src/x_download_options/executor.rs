use crate::constants::header_keys::X_DOWNLOAD_OPTIONS;
use crate::constants::header_values::X_DOWNLOAD_OPTIONS_NOOPEN;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions};
use crate::normalized_headers::NormalizedHeaders;

pub struct XDownloadOptions {
    options: NoopOptions,
}

impl XDownloadOptions {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl Default for XDownloadOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExecutor for XDownloadOptions {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_DOWNLOAD_OPTIONS, X_DOWNLOAD_OPTIONS_NOOPEN);

        Ok(())
    }
}
