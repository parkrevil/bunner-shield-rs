use super::options::CoopOptions;
use crate::constants::header_keys::CROSS_ORIGIN_OPENER_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct Coop {
    options: CoopOptions,
}

impl Coop {
    pub fn new(options: CoopOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Coop {
    type Options = CoopOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(CROSS_ORIGIN_OPENER_POLICY, self.options.policy.as_str());

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(CROSS_ORIGIN_OPENER_POLICY) {
            context.push_runtime_info(
                "coop",
                format!("Emitted Cross-Origin-Opener-Policy header: {value}"),
            );
        }

        Ok(())
    }
}
