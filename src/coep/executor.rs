use super::options::CoepOptions;
use crate::constants::header_keys::{
    CROSS_ORIGIN_EMBEDDER_POLICY, CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
};
use crate::executor::{
    ExecutorError, FeatureExecutor, ReportContext, ReportingConfig, ReportingEntry,
};
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
        let header_name = if self.options.is_report_only() {
            CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY
        } else {
            CROSS_ORIGIN_EMBEDDER_POLICY
        };

        headers.insert(header_name, self.options.policy.as_str());

        Ok(())
    }

    fn reporting_config(&self) -> Option<ReportingConfig> {
        let mut config = ReportingConfig::default();

        if let Some(group) = self.options.report_group_ref() {
            config
                .report_to
                .push(ReportingEntry::new("coep", group.header_value()));
        }

        if !self.options.reporting_endpoints().is_empty() {
            let value = self
                .options
                .reporting_endpoints()
                .iter()
                .map(|endpoint| endpoint.header_fragment())
                .collect::<Vec<_>>()
                .join(", ");

            config
                .reporting_endpoints
                .push(ReportingEntry::new("coep", value));
        }

        if config.is_empty() {
            None
        } else {
            Some(config)
        }
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        let header_name = if self.options.is_report_only() {
            CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY
        } else {
            CROSS_ORIGIN_EMBEDDER_POLICY
        };

        if let Some(value) = headers.get(header_name) {
            context.push_runtime_info("coep", format!("Emitted {} header: {value}", header_name));
        }

        Ok(())
    }
}
