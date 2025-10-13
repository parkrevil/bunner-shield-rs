use super::XdnsPrefetchControlOptions;
use crate::constants::header_keys::X_DNS_PREFETCH_CONTROL;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct XdnsPrefetchControl {
    options: XdnsPrefetchControlOptions,
}

impl XdnsPrefetchControl {
    pub fn new(options: XdnsPrefetchControlOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for XdnsPrefetchControl {
    type Options = XdnsPrefetchControlOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_DNS_PREFETCH_CONTROL, self.options.header_value());

        Ok(())
    }
}
