use super::CspOptions;
use crate::constants::header_keys::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, REPORT_TO, REPORTING_ENDPOINTS,
};
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext, ReportEntry, ReportSeverity};
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

        if let Some(group) = &self.options.report_group {
            headers.insert(REPORT_TO, group.header_value());
        }

        if !self.options.reporting_endpoints.is_empty() {
            let value = self
                .options
                .reporting_endpoints
                .iter()
                .map(|endpoint| endpoint.header_fragment())
                .collect::<Vec<_>>()
                .join(", ");
            headers.insert(REPORTING_ENDPOINTS, value);
        }

        Ok(())
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

        if let Some(report_to) = headers.get(REPORT_TO) {
            context.push(ReportEntry::runtime(
                "csp",
                ReportSeverity::Info,
                format!("Emitted Report-To header: {report_to}"),
            ));
        }

        if let Some(endpoints) = headers.get(REPORTING_ENDPOINTS) {
            let severity = if self.options.reporting_endpoints.is_empty() {
                ReportSeverity::Warning
            } else {
                ReportSeverity::Info
            };

            let message = if self.options.reporting_endpoints.is_empty() {
                format!(
                    "Emitted Reporting-Endpoints header without configured endpoints: {endpoints}",
                )
            } else {
                format!("Emitted Reporting-Endpoints header: {endpoints}")
            };

            context.push(ReportEntry::runtime("csp", severity, message));
        }

        Ok(())
    }
}
