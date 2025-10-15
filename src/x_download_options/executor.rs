use crate::constants::header_keys::X_DOWNLOAD_OPTIONS;
use crate::constants::header_values::X_DOWNLOAD_OPTIONS_NOOPEN;
use crate::executor::{ExecutorError, FeatureExecutor, NoopOptions, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct XDownloadOptions {
    options: NoopOptions,
}

impl XDownloadOptions {
    pub fn new() -> Self {
        Self {
            options: NoopOptions,
        }
    }
}

impl Default for XDownloadOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExecutor for XDownloadOptions {
    type Options = NoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError> {
        context.push_validation_info(
            "x-download-options",
            "Configured X-Download-Options policy: noopen",
        );

        Ok(())
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_DOWNLOAD_OPTIONS, X_DOWNLOAD_OPTIONS_NOOPEN);

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(X_DOWNLOAD_OPTIONS) {
            context.push_runtime_info(
                "x-download-options",
                format!("Emitted X-Download-Options header: {value}"),
            );
        }

        Ok(())
    }
}
