use super::options::CorpOptions;
use crate::constants::header_keys::CROSS_ORIGIN_RESOURCE_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct Corp {
    options: CorpOptions,
}

impl Corp {
    pub fn new(options: CorpOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Corp {
    type Options = CorpOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(CROSS_ORIGIN_RESOURCE_POLICY, self.options.policy.as_str());

        Ok(())
    }
}
