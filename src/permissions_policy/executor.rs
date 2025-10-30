use super::PermissionsPolicyOptions;
use crate::constants::header_keys::{
    FEATURE_POLICY, PERMISSIONS_POLICY, PERMISSIONS_POLICY_REPORT_ONLY,
};
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

fn fallback_key_for_options(options: &PermissionsPolicyOptions) -> Option<&'static str> {
    if options.should_emit_feature_policy_fallback() {
        Some(FEATURE_POLICY)
    } else {
        None
    }
}

crate::impl_dynamic_header_executor!(
    PermissionsPolicy,
    PermissionsPolicyOptions,
    header_key_for_options,
    fallback => fallback_key_for_options
);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
