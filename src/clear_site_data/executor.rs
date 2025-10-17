use super::ClearSiteDataOptions;
use crate::constants::header_keys::CLEAR_SITE_DATA;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
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

impl FeatureExecutor for ClearSiteData {
    type Options = ClearSiteDataOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(CLEAR_SITE_DATA, self.cached.cloned_header_value());

        Ok(())
    }
}
