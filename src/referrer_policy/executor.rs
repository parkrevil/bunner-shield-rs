use super::ReferrerPolicyOptions;
use crate::constants::header_keys::REFERRER_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct ReferrerPolicy {
    cached: CachedHeader<ReferrerPolicyOptions>,
}

impl ReferrerPolicy {
    pub fn new(options: ReferrerPolicyOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

impl FeatureExecutor for ReferrerPolicy {
    type Options = ReferrerPolicyOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(REFERRER_POLICY, self.cached.cloned_header_value());

        Ok(())
    }
}
