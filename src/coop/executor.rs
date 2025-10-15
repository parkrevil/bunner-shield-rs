use super::options::CoopOptions;
use crate::constants::header_keys::{
    CROSS_ORIGIN_OPENER_POLICY, CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
};
use crate::executor::{
    ExecutorError, FeatureExecutor, ReportContext, ReportingConfig, ReportingEntry,
};
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
        let header_name = if self.options.is_report_only() {
            CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY
        } else {
            CROSS_ORIGIN_OPENER_POLICY
        };

        headers.insert(header_name, self.options.policy.as_str());

        Ok(())
    }

    fn reporting_config(&self) -> Option<ReportingConfig> {
        let mut config = ReportingConfig::default();

        if let Some(group) = self.options.report_group_ref() {
            config
                .report_to
                .push(ReportingEntry::new("coop", group.header_value()));
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
                .push(ReportingEntry::new("coop", value));
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
            CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY
        } else {
            CROSS_ORIGIN_OPENER_POLICY
        };

        if let Some(value) = headers.get(header_name) {
            context.push_runtime_info("coop", format!("Emitted {} header: {value}", header_name));
        }

        Ok(())
    }
}
