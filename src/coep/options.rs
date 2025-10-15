use crate::constants::header_values::{COEP_CREDENTIALLESS, COEP_REQUIRE_CORP};
use crate::csp::{CspReportGroup, CspReportingEndpoint};
use crate::executor::{FeatureOptions, ReportContext};
use std::borrow::Cow;
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoepPolicy {
    RequireCorp,
    Credentialless,
}

impl CoepPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoepPolicy::RequireCorp => COEP_REQUIRE_CORP,
            CoepPolicy::Credentialless => COEP_CREDENTIALLESS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoepOptions {
    pub(crate) policy: CoepPolicy,
    pub(crate) report_only: bool,
    pub(crate) report_group: Option<CspReportGroup>,
    pub(crate) reporting_endpoints: Vec<CspReportingEndpoint>,
}

impl CoepOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CoepPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self
    }

    pub fn report_group(mut self, group: CspReportGroup) -> Self {
        self.report_group = Some(group);
        self
    }

    pub fn reporting_endpoint<'a>(
        mut self,
        name: impl Into<Cow<'a, str>>,
        url: impl Into<Cow<'a, str>>,
    ) -> Self {
        self.reporting_endpoints
            .push(CspReportingEndpoint::new(name, url));
        self
    }

    pub fn add_reporting_endpoint(mut self, endpoint: CspReportingEndpoint) -> Self {
        self.reporting_endpoints.push(endpoint);
        self
    }

    pub(crate) fn is_report_only(&self) -> bool {
        self.report_only
    }

    pub(crate) fn report_group_ref(&self) -> Option<&CspReportGroup> {
        self.report_group.as_ref()
    }

    pub(crate) fn reporting_endpoints(&self) -> &[CspReportingEndpoint] {
        &self.reporting_endpoints
    }
}

impl Default for CoepOptions {
    fn default() -> Self {
        Self {
            policy: CoepPolicy::RequireCorp,
            report_only: false,
            report_group: None,
            reporting_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoepOptionsError {
    #[error("coep report-only mode requires a report group")]
    ReportOnlyWithoutGroup,
    #[error(
        "coep reporting endpoint name must contain only ASCII alphanumeric characters, hyphen, underscore, or dot (received {0})"
    )]
    InvalidReportingEndpointName(String),
    #[error("coep reporting endpoint url must be a valid https URL (received {0})")]
    InvalidReportingEndpointUrl(String),
    #[error("coep reporting endpoint names must be unique (duplicate {0})")]
    DuplicateReportingEndpoint(String),
}

impl FeatureOptions for CoepOptions {
    type Error = CoepOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.report_only && self.report_group.is_none() {
            return Err(CoepOptionsError::ReportOnlyWithoutGroup);
        }

        Self::validate_reporting_endpoints(&self.reporting_endpoints)?;

        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "coep",
            format!(
                "Configured Cross-Origin-Embedder-Policy: {}",
                self.policy.as_str()
            ),
        );

        if let Some(group) = &self.report_group {
            context.push_validation_info(
                "coep",
                format!("Configured Report-To group: {}", group.name()),
            );
        }

        if !self.reporting_endpoints.is_empty() {
            let summary = self
                .reporting_endpoints
                .iter()
                .map(|endpoint| format!("{} -> {}", endpoint.name(), endpoint.url()))
                .collect::<Vec<_>>()
                .join(", ");

            context.push_validation_info(
                "coep",
                format!("Configured reporting endpoints: {}", summary),
            );
        }
    }
}

impl CoepOptions {
    fn validate_reporting_endpoints(
        endpoints: &[CspReportingEndpoint],
    ) -> Result<(), CoepOptionsError> {
        let mut seen = HashSet::new();

        for endpoint in endpoints {
            let name = endpoint.name();

            if name.trim().is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
            {
                return Err(CoepOptionsError::InvalidReportingEndpointName(
                    name.to_string(),
                ));
            }

            let lowered = name.to_ascii_lowercase();
            if !seen.insert(lowered) {
                return Err(CoepOptionsError::DuplicateReportingEndpoint(
                    name.to_string(),
                ));
            }

            let url = endpoint.url();

            if url.trim().is_empty() {
                return Err(CoepOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }

            let parsed = Url::parse(url)
                .map_err(|_| CoepOptionsError::InvalidReportingEndpointUrl(url.to_string()))?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(CoepOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }
        }

        Ok(())
    }
}
