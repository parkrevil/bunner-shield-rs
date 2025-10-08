use super::CspOptions;
use crate::constants::header::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO,
};
use crate::executor::Executor;

#[allow(dead_code)]
pub struct Csp<'a> {
    options: &'a CspOptions,
}

impl<'a> Csp<'a> {
    pub fn new(options: &'a CspOptions) -> Self {
        Self { options }
    }
}

impl<'a> Executor for Csp<'a> {
    type Output = Vec<(String, String)>;

    fn execute(&self) -> Self::Output {
        let mut pairs = Vec::with_capacity(2);

        let header_name = if self.options.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        pairs.push((header_name.to_string(), self.options.serialize()));

        if let Some(group) = &self.options.report_group {
            pairs.push((REPORT_TO.to_string(), group.to_header_value()));
        }

        pairs
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
