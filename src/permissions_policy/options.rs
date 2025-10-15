use crate::csp::{CspReportGroup, CspReportingEndpoint};
use crate::executor::{FeatureOptions, ReportContext};
use std::borrow::Cow;
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsPolicyOptions {
    policy: String,
    report_only: bool,
    report_group: Option<CspReportGroup>,
    reporting_endpoints: Vec<CspReportingEndpoint>,
}

impl PermissionsPolicyOptions {
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
            report_only: false,
            report_group: None,
            reporting_endpoints: Vec::new(),
        }
    }

    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = policy.into();
        self
    }

    pub(crate) fn header_value(&self) -> &str {
        self.policy.as_str()
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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionsPolicyOptionsError {
    #[error("permissions policy value must not be empty")]
    EmptyPolicy,
    #[error("permissions policy report-only mode requires a report group")]
    ReportOnlyWithoutGroup,
    #[error(
        "permissions policy reporting endpoint name must contain only ASCII alphanumeric characters, hyphen, underscore, or dot (received {0})"
    )]
    InvalidReportingEndpointName(String),
    #[error("permissions policy reporting endpoint url must be a valid https URL (received {0})")]
    InvalidReportingEndpointUrl(String),
    #[error("permissions policy reporting endpoint names must be unique (duplicate {0})")]
    DuplicateReportingEndpoint(String),
}

impl FeatureOptions for PermissionsPolicyOptions {
    type Error = PermissionsPolicyOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.policy.trim().is_empty() {
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        } else if self.report_only && self.report_group.is_none() {
            Err(PermissionsPolicyOptionsError::ReportOnlyWithoutGroup)
        } else {
            Self::validate_reporting_endpoints(&self.reporting_endpoints)
        }
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "permissions-policy",
            format!("Configured Permissions-Policy: {}", self.policy.trim()),
        );

        if let Some(group) = &self.report_group {
            context.push_validation_info(
                "permissions-policy",
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
                "permissions-policy",
                format!("Configured reporting endpoints: {}", summary),
            );
        }
    }
}

impl PermissionsPolicyOptions {
    fn validate_reporting_endpoints(
        endpoints: &[CspReportingEndpoint],
    ) -> Result<(), PermissionsPolicyOptionsError> {
        let mut seen = HashSet::new();

        for endpoint in endpoints {
            let name = endpoint.name();

            if name.trim().is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
            {
                return Err(PermissionsPolicyOptionsError::InvalidReportingEndpointName(
                    name.to_string(),
                ));
            }

            let lowered = name.to_ascii_lowercase();
            if !seen.insert(lowered) {
                return Err(PermissionsPolicyOptionsError::DuplicateReportingEndpoint(
                    name.to_string(),
                ));
            }

            let url = endpoint.url();

            if url.trim().is_empty() {
                return Err(PermissionsPolicyOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }

            let parsed = Url::parse(url).map_err(|_| {
                PermissionsPolicyOptionsError::InvalidReportingEndpointUrl(url.to_string())
            })?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(PermissionsPolicyOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
