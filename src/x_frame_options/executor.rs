use super::XFrameOptionsOptions;
use crate::constants::header_keys::X_FRAME_OPTIONS;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct XFrameOptions {
    cached: CachedHeader<XFrameOptionsOptions>,
}

impl XFrameOptions {
    pub fn new(options: XFrameOptionsOptions) -> Self {
        let header_value = options.header_value().to_string();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

impl FeatureExecutor for XFrameOptions {
    type Options = XFrameOptionsOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_FRAME_OPTIONS, self.cached.cloned_header_value());

        Ok(())
    }
}
