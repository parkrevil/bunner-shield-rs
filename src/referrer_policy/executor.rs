use super::ReferrerPolicyOptions;
use crate::constants::header_keys::REFERRER_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct ReferrerPolicy {
    options: ReferrerPolicyOptions,
}

impl ReferrerPolicy {
    pub fn new(options: ReferrerPolicyOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for ReferrerPolicy {
    type Options = ReferrerPolicyOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(REFERRER_POLICY, self.options.header_value());

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(REFERRER_POLICY) {
            context.push_runtime_info(
                "referrer-policy",
                format!("Emitted Referrer-Policy header: {value}"),
            );
        }

        Ok(())
    }
}
