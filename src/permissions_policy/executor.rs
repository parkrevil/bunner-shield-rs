use super::PermissionsPolicyOptions;
use crate::constants::header_keys::PERMISSIONS_POLICY;
use crate::executor::CachedHeader;
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

crate::impl_cached_header_executor!(
    PermissionsPolicy,
    PermissionsPolicyOptions,
    PERMISSIONS_POLICY
);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
