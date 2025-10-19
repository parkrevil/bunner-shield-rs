use super::HstsOptions;
use crate::constants::header_keys::STRICT_TRANSPORT_SECURITY;
use crate::executor::CachedHeader;
use std::borrow::Cow;

pub struct Hsts {
    cached: CachedHeader<HstsOptions>,
}

impl Hsts {
    pub fn new(options: HstsOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(Hsts, HstsOptions, STRICT_TRANSPORT_SECURITY);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
