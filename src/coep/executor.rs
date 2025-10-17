use super::options::CoepOptions;
use crate::constants::header_keys::CROSS_ORIGIN_EMBEDDER_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct Coep {
    cached: CachedHeader<CoepOptions>,
}

impl Coep {
    pub fn new(options: CoepOptions) -> Self {
        let header_value = options.policy.as_str().to_string();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

impl FeatureExecutor for Coep {
    type Options = CoepOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(
            CROSS_ORIGIN_EMBEDDER_POLICY,
            self.cached.cloned_header_value(),
        );

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
