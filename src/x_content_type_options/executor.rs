use crate::constants::header_keys::X_CONTENT_TYPE_OPTIONS;
use crate::constants::header_values::NOSNIFF;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct XContentTypeOptions {
    options: NoopOptions,
}

impl XContentTypeOptions {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl FeatureExecutor for XContentTypeOptions {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError> {
        context.push_validation_info(
            "x-content-type-options",
            "Configured X-Content-Type-Options policy: nosniff",
        );

        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(X_CONTENT_TYPE_OPTIONS) {
            context.push_runtime_info(
                "x-content-type-options",
                format!("Emitted X-Content-Type-Options header: {value}"),
            );
        }

        Ok(())
    }
}
