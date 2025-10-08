use super::CspOptions;

pub const HEADER_CONTENT_SECURITY_POLICY: &str = "Content-Security-Policy";
pub const HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY: &str = "Content-Security-Policy-Report-Only";
pub const HEADER_REPORT_TO: &str = "Report-To";

pub fn header_pairs(options: &CspOptions) -> Vec<(String, String)> {
    let mut pairs = Vec::with_capacity(2);

    let header_name = if options.report_only {
        HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY
    } else {
        HEADER_CONTENT_SECURITY_POLICY
    };

    pairs.push((header_name.to_string(), options.serialize()));

    if let Some(group) = &options.report_group {
        pairs.push((HEADER_REPORT_TO.to_string(), group.to_header_value()));
    }

    pairs
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
