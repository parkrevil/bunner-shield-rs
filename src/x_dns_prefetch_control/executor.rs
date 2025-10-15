use super::XdnsPrefetchControlOptions;
use crate::constants::header_keys::X_DNS_PREFETCH_CONTROL;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
use crate::normalized_headers::NormalizedHeaders;

pub struct XdnsPrefetchControl {
    options: XdnsPrefetchControlOptions,
}

impl XdnsPrefetchControl {
    pub fn new(options: XdnsPrefetchControlOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for XdnsPrefetchControl {
    type Options = XdnsPrefetchControlOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(X_DNS_PREFETCH_CONTROL, self.options.header_value());

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if let Some(value) = headers.get(X_DNS_PREFETCH_CONTROL) {
            context.push_runtime_info(
                "x-dns-prefetch-control",
                format!("Emitted X-DNS-Prefetch-Control header: {value}"),
            );
        }

        Ok(())
    }
}
