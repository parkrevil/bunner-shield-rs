use super::options::CoepOptions;
use crate::constants::header_keys::CROSS_ORIGIN_EMBEDDER_POLICY;
use crate::executor::CachedHeader;
use std::borrow::Cow;

pub struct Coep {
    cached: CachedHeader<CoepOptions>,
}

impl Coep {
    pub fn new(options: CoepOptions) -> Self {
        let header_value = options.policy.as_str();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(Coep, CoepOptions, CROSS_ORIGIN_EMBEDDER_POLICY);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
