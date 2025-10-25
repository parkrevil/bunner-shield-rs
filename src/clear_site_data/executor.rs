use super::ClearSiteDataOptions;
use crate::constants::header_keys::CLEAR_SITE_DATA;
use crate::executor::CachedHeader;
#[cfg(test)]
use crate::executor::FeatureExecutor;
use std::borrow::Cow;

pub struct ClearSiteData {
    cached: CachedHeader<ClearSiteDataOptions>,
}

impl ClearSiteData {
    pub fn new(options: ClearSiteDataOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

crate::impl_cached_header_executor!(ClearSiteData, ClearSiteDataOptions, CLEAR_SITE_DATA);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
