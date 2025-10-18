use super::XdnsPrefetchControlOptions;
use crate::constants::header_keys::X_DNS_PREFETCH_CONTROL;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct XdnsPrefetchControl {
    cached: CachedHeader<XdnsPrefetchControlOptions>,
}

impl XdnsPrefetchControl {
    pub fn new(options: XdnsPrefetchControlOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

impl FeatureExecutor for XdnsPrefetchControl {
    type Options = XdnsPrefetchControlOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_DNS_PREFETCH_CONTROL, self.cached.cloned_header_value());

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
