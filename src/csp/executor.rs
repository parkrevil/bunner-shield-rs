use super::CspOptions;
use crate::constants::header_keys::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY};
use crate::executor::{
    ExecutorError, FeatureExecutor, ReportContext, ReportEntry, ReportSeverity, ReportingConfig,
    ReportingEntry,
};
use crate::normalized_headers::NormalizedHeaders;

pub struct Csp {
    options: CspOptions,
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for Csp {
    type Options = CspOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let header_name = if self.options.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        headers.insert(header_name, self.options.header_value());

        Ok(())
    }

    fn reporting_config(&self) -> Option<ReportingConfig> {
        let mut config = ReportingConfig::default();

        if let Some(group) = &self.options.report_group {
            config
                .report_to
                .push(ReportingEntry::new("csp", group.header_value()));
        }

        if !self.options.reporting_endpoints.is_empty() {
            let value = self
                .options
                .reporting_endpoints
                .iter()
                .map(|endpoint| endpoint.header_fragment())
                .collect::<Vec<_>>()
                .join(", ");

            config
                .reporting_endpoints
                .push(ReportingEntry::new("csp", value));
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
        let policy_header = if self.options.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        if let Some(value) = headers.get(policy_header) {
            context.push(ReportEntry::runtime(
                "csp",
                ReportSeverity::Info,
                format!("Emitted {policy_header} header: {value}"),
            ));
        }

        Ok(())
    }
}
