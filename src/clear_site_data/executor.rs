use super::ClearSiteDataOptions;
use crate::constants::header_keys::CLEAR_SITE_DATA;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct ClearSiteData {
    options: ClearSiteDataOptions,
}

impl ClearSiteData {
    pub fn new(options: ClearSiteDataOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for ClearSiteData {
    type Options = ClearSiteDataOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(CLEAR_SITE_DATA, self.options.header_value());

        Ok(())
    }
}
