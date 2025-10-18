use super::options::CoopOptions;
use crate::constants::header_keys::CROSS_ORIGIN_OPENER_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct Coop {
    cached: CachedHeader<CoopOptions>,
}

impl Coop {
    pub fn new(options: CoopOptions) -> Self {
        let header_value = options.policy.as_str();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

impl FeatureExecutor for Coop {
    type Options = CoopOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(
            CROSS_ORIGIN_OPENER_POLICY,
            self.cached.cloned_header_value(),
        );

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
