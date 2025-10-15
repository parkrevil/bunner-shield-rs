use super::options::CoepOptions;
use crate::constants::header_keys::CROSS_ORIGIN_EMBEDDER_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct Coep {
    options: CoepOptions,
}

impl Coep {
    pub fn new(options: CoepOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Coep {
    type Options = CoepOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(CROSS_ORIGIN_EMBEDDER_POLICY, self.options.policy.as_str());

        Ok(())
    }
}
