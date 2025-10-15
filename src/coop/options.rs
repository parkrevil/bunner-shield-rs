use crate::constants::header_values::{
    COOP_SAME_ORIGIN, COOP_SAME_ORIGIN_ALLOW_POPUPS, COOP_UNSAFE_NONE,
};
use crate::csp::{CspReportGroup, CspReportingEndpoint};
use crate::executor::{FeatureOptions, ReportContext};
use std::borrow::Cow;
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoopPolicy {
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone,
}

impl CoopPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoopPolicy::SameOrigin => COOP_SAME_ORIGIN,
            CoopPolicy::SameOriginAllowPopups => COOP_SAME_ORIGIN_ALLOW_POPUPS,
            CoopPolicy::UnsafeNone => COOP_UNSAFE_NONE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoopOptions {
    pub(crate) policy: CoopPolicy,
    pub(crate) report_only: bool,
    pub(crate) report_group: Option<CspReportGroup>,
    pub(crate) reporting_endpoints: Vec<CspReportingEndpoint>,
}

impl CoopOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CoopPolicy) -> Self {
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

impl Default for CoopOptions {
    fn default() -> Self {
        Self {
            policy: CoopPolicy::SameOrigin,
            report_only: false,
            report_group: None,
            reporting_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoopOptionsError {
    #[error("coop report-only mode requires a report group")]
    ReportOnlyWithoutGroup,
    #[error(
        "coop reporting endpoint name must contain only ASCII alphanumeric characters, hyphen, underscore, or dot (received {0})"
    )]
    InvalidReportingEndpointName(String),
    #[error("coop reporting endpoint url must be a valid https URL (received {0})")]
    InvalidReportingEndpointUrl(String),
    #[error("coop reporting endpoint names must be unique (duplicate {0})")]
    DuplicateReportingEndpoint(String),
}

impl FeatureOptions for CoopOptions {
    type Error = CoopOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.report_only && self.report_group.is_none() {
            return Err(CoopOptionsError::ReportOnlyWithoutGroup);
        }

        Self::validate_reporting_endpoints(&self.reporting_endpoints)?;

        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "coop",
            format!(
                "Configured Cross-Origin-Opener-Policy: {}",
                self.policy.as_str()
            ),
        );

        if let Some(group) = &self.report_group {
            context.push_validation_info(
                "coop",
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
                "coop",
                format!("Configured reporting endpoints: {}", summary),
            );
        }
    }
}

impl CoopOptions {
    fn validate_reporting_endpoints(
        endpoints: &[CspReportingEndpoint],
    ) -> Result<(), CoopOptionsError> {
        let mut seen = HashSet::new();

        for endpoint in endpoints {
            let name = endpoint.name();

            if name.trim().is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
            {
                return Err(CoopOptionsError::InvalidReportingEndpointName(
                    name.to_string(),
                ));
            }

            let lowered = name.to_ascii_lowercase();
            if !seen.insert(lowered) {
                return Err(CoopOptionsError::DuplicateReportingEndpoint(
                    name.to_string(),
                ));
            }

            let url = endpoint.url();

            if url.trim().is_empty() {
                return Err(CoopOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }

            let parsed = Url::parse(url)
                .map_err(|_| CoopOptionsError::InvalidReportingEndpointUrl(url.to_string()))?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(CoopOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }
        }

        Ok(())
    }
}
