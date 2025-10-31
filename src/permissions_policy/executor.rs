use super::PermissionsPolicyOptions;
use crate::constants::header_keys::{PERMISSIONS_POLICY, PERMISSIONS_POLICY_REPORT_ONLY};
use crate::executor::{DynamicHeaderCache, PolicyMode};
use std::borrow::Cow;

pub struct PermissionsPolicy {
    cached: DynamicHeaderCache<PermissionsPolicyOptions>,
}

impl PermissionsPolicy {
    pub fn new(options: PermissionsPolicyOptions) -> Self {
        let header_value = options.header_value().to_string();
        Self {
            cached: DynamicHeaderCache::new(options, Cow::Owned(header_value)),
        }
    }
}

fn header_key_for_options(options: &PermissionsPolicyOptions) -> &'static str {
    match options.mode() {
        PolicyMode::Enforce => PERMISSIONS_POLICY,
        PolicyMode::ReportOnly => PERMISSIONS_POLICY_REPORT_ONLY,
    }
}

crate::impl_dynamic_header_executor!(PermissionsPolicy, PermissionsPolicyOptions, header_key_for_options);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
