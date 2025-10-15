use super::options::NelOptions;
use crate::constants::header_keys::{NEL, REPORT_TO};
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct Nel {
    options: NelOptions,
}

impl Nel {
    pub fn new(options: NelOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Nel {
    type Options = NelOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(NEL, self.options.header_value());

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(NEL) {
            context.push_runtime_info("nel", format!("Emitted NEL header: {value}"));
        }

        if headers.get(REPORT_TO).is_none() {
            context.push_runtime_warning(
                "nel",
                "NEL header emitted without matching Report-To header",
            );
        }

        Ok(())
    }
}
