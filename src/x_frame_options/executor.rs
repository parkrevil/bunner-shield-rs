use super::XFrameOptionsOptions;
use crate::constants::header_keys::X_FRAME_OPTIONS;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct XFrameOptions {
    options: XFrameOptionsOptions,
}

impl XFrameOptions {
    pub fn new(options: XFrameOptionsOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for XFrameOptions {
    type Options = XFrameOptionsOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_FRAME_OPTIONS, self.options.header_value());

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(X_FRAME_OPTIONS) {
            context.push_runtime_info(
                "x-frame-options",
                format!("Emitted X-Frame-Options header: {value}"),
            );
        }

        Ok(())
    }
}
