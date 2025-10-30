use super::options::CoepOptions;
use crate::constants::header_keys::{
    CROSS_ORIGIN_EMBEDDER_POLICY, CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
};
use crate::executor::{DynamicHeaderCache, ExecutorError, FeatureExecutor, PolicyMode};
use std::borrow::Cow;

pub struct Coep {
    cached: DynamicHeaderCache<CoepOptions>,
}

impl Coep {
    pub fn new(options: CoepOptions) -> Self {
        let header_value = options.policy.as_str();
        Self {
            cached: DynamicHeaderCache::new(options, Cow::Borrowed(header_value)),
        }
    }
}

fn header_key_for_options(options: &CoepOptions) -> &'static str {
    match options.mode() {
        PolicyMode::Enforce => CROSS_ORIGIN_EMBEDDER_POLICY,
        PolicyMode::ReportOnly => CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
    }
}

impl FeatureExecutor for Coep {
    type Options = CoepOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(
        &self,
        headers: &mut crate::normalized_headers::NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        let options = self.cached.options();
        if matches!(options.mode(), PolicyMode::ReportOnly) {
            headers.remove(CROSS_ORIGIN_EMBEDDER_POLICY);
        }

        let header_key = header_key_for_options(options);
        headers.insert(header_key, self.cached.cloned_header_value());
        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
