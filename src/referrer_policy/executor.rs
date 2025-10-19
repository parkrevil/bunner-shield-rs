use super::ReferrerPolicyOptions;
use crate::constants::header_keys::REFERRER_POLICY;
use crate::executor::CachedHeader;
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

crate::impl_cached_header_executor!(ReferrerPolicy, ReferrerPolicyOptions, REFERRER_POLICY);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
