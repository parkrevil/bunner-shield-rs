use super::options::CorpOptions;
use crate::constants::header_keys::CROSS_ORIGIN_RESOURCE_POLICY;
use crate::executor::CachedHeader;
use std::borrow::Cow;

pub struct Corp {
    cached: CachedHeader<CorpOptions>,
}

impl Corp {
    pub fn new(options: CorpOptions) -> Self {
        let header_value = options.policy.as_str();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(Corp, CorpOptions, CROSS_ORIGIN_RESOURCE_POLICY);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
