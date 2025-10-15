use crate::constants::header_keys::X_POWERED_BY;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct XPoweredBy {
    options: NoopOptions,
}

impl XPoweredBy {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl FeatureExecutor for XPoweredBy {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError> {
        context.push_validation_info("x-powered-by", "Configured to remove X-Powered-By header");

        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.remove(X_POWERED_BY);

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if headers.get(X_POWERED_BY).is_none() {
            context.push_runtime_info("x-powered-by", "Removed X-Powered-By header");
        }

        Ok(())
    }
}
