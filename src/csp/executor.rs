use super::CspOptions;
use crate::constants::header::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO,
};

pub fn header_pairs(options: &CspOptions) -> Vec<(String, String)> {
    let mut pairs = Vec::with_capacity(2);

    let header_name = if options.report_only {
        CONTENT_SECURITY_POLICY_REPORT_ONLY
    } else {
        CONTENT_SECURITY_POLICY
    };

    pairs.push((header_name.to_string(), options.serialize()));

    if let Some(group) = &options.report_group {
        pairs.push((REPORT_TO.to_string(), group.to_header_value()));
    }

    pairs
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
