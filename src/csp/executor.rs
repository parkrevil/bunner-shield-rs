use super::CspOptions;
use crate::constants::header::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO,
};
use crate::executor::Executor;

pub struct Csp {
    options: CspOptions,
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        Self { options }
    }
}

impl Executor for Csp {
    type Output = Vec<(String, String)>;

    fn validate_options(&self) -> Result<(), String> {
        self.options
            .clone()
            .validate()
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

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
