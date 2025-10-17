use super::HstsOptions;
use crate::constants::header_keys::STRICT_TRANSPORT_SECURITY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
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

impl FeatureExecutor for Hsts {
    type Options = HstsOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(STRICT_TRANSPORT_SECURITY, self.cached.cloned_header_value());

        Ok(())
    }
}
