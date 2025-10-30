use super::options::CoopOptions;
use crate::constants::header_keys::{
    CROSS_ORIGIN_OPENER_POLICY, CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
};
use crate::executor::{DynamicHeaderCache, PolicyMode};
use std::borrow::Cow;

pub struct Coop {
    cached: DynamicHeaderCache<CoopOptions>,
}

impl Coop {
    pub fn new(options: CoopOptions) -> Self {
        let header_value = options.policy.as_str();
        Self {
            cached: DynamicHeaderCache::new(options, Cow::Borrowed(header_value)),
        }
    }
}

fn header_key_for_options(options: &CoopOptions) -> &'static str {
    match options.mode() {
        PolicyMode::Enforce => CROSS_ORIGIN_OPENER_POLICY,
        PolicyMode::ReportOnly => CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
    }
}

crate::impl_dynamic_header_executor!(Coop, CoopOptions, header_key_for_options);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
