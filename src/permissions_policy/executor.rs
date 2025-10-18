use super::PermissionsPolicyOptions;
use crate::constants::header_keys::PERMISSIONS_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct PermissionsPolicy {
    cached: CachedHeader<PermissionsPolicyOptions>,
}

impl PermissionsPolicy {
    pub fn new(options: PermissionsPolicyOptions) -> Self {
        let header_value = options.header_value().to_string();
        Self {
            cached: CachedHeader::new(options, Cow::Owned(header_value)),
        }
    }
}

impl FeatureExecutor for PermissionsPolicy {
    type Options = PermissionsPolicyOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(PERMISSIONS_POLICY, self.cached.cloned_header_value());

        Ok(())
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
