use super::XFrameOptionsOptions;
use crate::constants::header_keys::X_FRAME_OPTIONS;
use crate::executor::CachedHeader;
use std::borrow::Cow;

pub struct XFrameOptions {
    cached: CachedHeader<XFrameOptionsOptions>,
}

impl XFrameOptions {
    pub fn new(options: XFrameOptionsOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(XFrameOptions, XFrameOptionsOptions, X_FRAME_OPTIONS);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
