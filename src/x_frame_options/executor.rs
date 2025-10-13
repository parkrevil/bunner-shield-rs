use super::XFrameOptionsOptions;
use crate::constants::header_keys::X_FRAME_OPTIONS;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct XFrameOptions {
    options: XFrameOptionsOptions,
}

impl XFrameOptions {
    pub fn new(options: XFrameOptionsOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for XFrameOptions {
    type Options = XFrameOptionsOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_FRAME_OPTIONS, self.options.serialize());

        Ok(())
    }
}
