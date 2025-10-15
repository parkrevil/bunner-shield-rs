use super::options::CoepOptions;
use crate::constants::header_keys::CROSS_ORIGIN_EMBEDDER_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct Coep {
    options: CoepOptions,
}

impl Coep {
    pub fn new(options: CoepOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Coep {
    type Options = CoepOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let header_value = self.options.policy.as_str();

        headers.insert(CROSS_ORIGIN_EMBEDDER_POLICY, header_value);

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(CROSS_ORIGIN_EMBEDDER_POLICY) {
            context.push_runtime_info(
                "coep",
                format!("Emitted Cross-Origin-Embedder-Policy header: {value}"),
            );
        }

        Ok(())
    }
}
