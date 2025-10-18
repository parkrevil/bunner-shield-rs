use super::options::CorpOptions;
use crate::constants::header_keys::CROSS_ORIGIN_RESOURCE_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct Corp {
    cached: CachedHeader<CorpOptions>,
}

impl Corp {
    pub fn new(options: CorpOptions) -> Self {
        let header_value = options.policy.as_str().to_string();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

impl FeatureExecutor for Corp {
    type Options = CorpOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(
            CROSS_ORIGIN_RESOURCE_POLICY,
            self.cached.cloned_header_value(),
        );

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
