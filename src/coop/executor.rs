use super::options::CoopOptions;
use crate::constants::header_keys::CROSS_ORIGIN_OPENER_POLICY;
use crate::executor::CachedHeader;
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

crate::impl_cached_header_executor!(Coop, CoopOptions, CROSS_ORIGIN_OPENER_POLICY);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
