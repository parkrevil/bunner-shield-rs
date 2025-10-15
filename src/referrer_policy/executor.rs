use super::ReferrerPolicyOptions;
use crate::constants::header_keys::REFERRER_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct ReferrerPolicy {
    options: ReferrerPolicyOptions,
}

impl ReferrerPolicy {
    pub fn new(options: ReferrerPolicyOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for ReferrerPolicy {
    type Options = ReferrerPolicyOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(REFERRER_POLICY, self.options.header_value());

        Ok(())
    }
}
