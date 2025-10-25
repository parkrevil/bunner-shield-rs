use super::XdnsPrefetchControlOptions;
use crate::constants::header_keys::X_DNS_PREFETCH_CONTROL;
use crate::executor::CachedHeader;
use std::borrow::Cow;

pub struct XdnsPrefetchControl {
    cached: CachedHeader<XdnsPrefetchControlOptions>,
}

impl XdnsPrefetchControl {
    pub fn new(options: XdnsPrefetchControlOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(
    XdnsPrefetchControl,
    XdnsPrefetchControlOptions,
    X_DNS_PREFETCH_CONTROL
);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
