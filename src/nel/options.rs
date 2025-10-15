use crate::executor::{FeatureOptions, ReportContext};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

const DEFAULT_MAX_AGE: u64 = 2_592_000; // 30 days

#[derive(Debug, Clone, PartialEq)]
pub struct NelOptions {
    pub(crate) report_to: String,
    pub(crate) max_age: u64,
    pub(crate) include_subdomains: bool,
    pub(crate) failure_fraction: Option<f32>,
    pub(crate) success_fraction: Option<f32>,
    pub(crate) reporting_endpoints: Vec<NelReportingEndpoint>,
}

impl NelOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn report_to(mut self, report_to: impl Into<String>) -> Self {
        self.report_to = report_to.into();
        self
    }

    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = seconds;
        self
    }

    pub fn include_subdomains(mut self, include: bool) -> Self {
        self.include_subdomains = include;
        self
    }

    pub fn failure_fraction(mut self, fraction: f32) -> Self {
        self.failure_fraction = Some(fraction);
        self
    }

    pub fn success_fraction(mut self, fraction: f32) -> Self {
        self.success_fraction = Some(fraction);
        self
    }

    pub fn reporting_endpoint(mut self, name: impl Into<String>, url: impl Into<String>) -> Self {
        self.reporting_endpoints
            .push(NelReportingEndpoint::new(name, url));
        self
    }

    pub fn add_reporting_endpoint(mut self, endpoint: NelReportingEndpoint) -> Self {
        self.reporting_endpoints.push(endpoint);
        self
    }

    pub fn reporting_endpoints(&self) -> &[NelReportingEndpoint] {
        &self.reporting_endpoints
    }

    pub(crate) fn header_value(&self) -> String {
        let mut fields = Vec::new();
        fields.push(format!("\"report_to\":\"{}\"", self.report_to));
        fields.push(format!("\"max_age\":{}", self.max_age));

        if self.include_subdomains {
            fields.push("\"include_subdomains\":true".to_string());
        }

        if let Some(fraction) = self.failure_fraction {
            fields.push(format!(
                "\"failure_fraction\":{}",
                format_fraction(fraction)
            ));
        }

        if let Some(fraction) = self.success_fraction {
            fields.push(format!(
                "\"success_fraction\":{}",
                format_fraction(fraction)
            ));
        }

        format!("{{{}}}", fields.join(","))
    }

    pub(crate) fn report_to_header_value(&self) -> Option<String> {
        if self.reporting_endpoints.is_empty() {
            return None;
        }

        let mut fields = vec![
            format!("\"group\":\"{}\"", self.report_to),
            format!("\"max_age\":{}", self.max_age),
        ];

        if self.include_subdomains {
            fields.push("\"include_subdomains\":true".to_string());
        }

        if let Some(fraction) = self.failure_fraction {
            fields.push(format!(
                "\"failure_fraction\":{}",
                format_fraction(fraction)
            ));
        }

        if let Some(fraction) = self.success_fraction {
            fields.push(format!(
                "\"success_fraction\":{}",
                format_fraction(fraction)
            ));
        }

        let endpoints = self
            .reporting_endpoints
            .iter()
            .map(|endpoint| endpoint.report_to_fragment())
            .collect::<Vec<_>>()
            .join(",");

        fields.push(format!("\"endpoints\":[{}]", endpoints));

        Some(format!("{{{}}}", fields.join(",")))
    }

    pub(crate) fn reporting_endpoints_header_value(&self) -> Option<String> {
        if self.reporting_endpoints.is_empty() {
            return None;
        }

        Some(
            self.reporting_endpoints
                .iter()
                .map(|endpoint| endpoint.reporting_endpoints_fragment())
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

impl Default for NelOptions {
    fn default() -> Self {
        Self {
            report_to: "default".to_string(),
            max_age: DEFAULT_MAX_AGE,
            include_subdomains: false,
            failure_fraction: None,
            success_fraction: None,
            reporting_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NelReportingEndpoint {
    name: String,
    url: String,
}

impl NelReportingEndpoint {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into().trim().to_string(),
            url: url.into().trim().to_string(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn report_to_fragment(&self) -> String {
        format!("{{\"url\":\"{}\"}}", self.url)
    }

    fn reporting_endpoints_fragment(&self) -> String {
        format!("{}=\"{}\"", self.name, self.url)
    }
}

impl FeatureOptions for NelOptions {
    type Error = NelOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.report_to.trim().is_empty() {
            return Err(NelOptionsError::EmptyReportTo);
        }

        if self.max_age == 0 {
            return Err(NelOptionsError::InvalidMaxAge);
        }

        if let Some(fraction) = self
            .failure_fraction
            .filter(|fraction| !(0.0..=1.0).contains(fraction))
        {
            return Err(NelOptionsError::InvalidFailureFraction(fraction));
        }

        if let Some(fraction) = self
            .success_fraction
            .filter(|fraction| !(0.0..=1.0).contains(fraction))
        {
            return Err(NelOptionsError::InvalidSuccessFraction(fraction));
        }

        Self::validate_reporting_endpoints(&self.reporting_endpoints)?;

        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        let mut attributes = vec![
            format!("report_to=`{}`", self.report_to),
            format!("max_age={}", self.max_age),
            format!("include_subdomains={}", self.include_subdomains),
        ];

        if let Some(fraction) = self.failure_fraction {
            attributes.push(format!("failure_fraction={}", format_fraction(fraction)));
        }

        if let Some(fraction) = self.success_fraction {
            attributes.push(format!("success_fraction={}", format_fraction(fraction)));
        }

        context.push_validation_info(
            "nel",
            format!("Configured NEL policy: {}", attributes.join(", ")),
        );

        if !self.reporting_endpoints.is_empty() {
            let summary = self
                .reporting_endpoints
                .iter()
                .map(|endpoint| format!("{} -> {}", endpoint.name(), endpoint.url()))
                .collect::<Vec<_>>()
                .join(", ");

            context.push_validation_info(
                "nel",
                format!("Configured reporting endpoints: {}", summary),
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum NelOptionsError {
    #[error("nel report_to value must not be empty")]
    EmptyReportTo,
    #[error("nel max_age must be greater than zero")]
    InvalidMaxAge,
    #[error("nel failure_fraction must be between 0.0 and 1.0 (received {0})")]
    InvalidFailureFraction(f32),
    #[error("nel success_fraction must be between 0.0 and 1.0 (received {0})")]
    InvalidSuccessFraction(f32),
    #[error(
        "nel reporting endpoint name must contain only ASCII alphanumeric characters, hyphen, underscore, or dot (received {0})"
    )]
    InvalidReportingEndpointName(String),
    #[error("nel reporting endpoint url must be a valid https URL (received {0})")]
    InvalidReportingEndpointUrl(String),
    #[error("nel reporting endpoint names must be unique (duplicate {0})")]
    DuplicateReportingEndpoint(String),
}

impl NelOptions {
    fn validate_reporting_endpoints(
        endpoints: &[NelReportingEndpoint],
    ) -> Result<(), NelOptionsError> {
        let mut seen = HashSet::new();

        for endpoint in endpoints {
            let name = endpoint.name();

            if name.trim().is_empty() || !name.chars().all(valid_endpoint_name_char) {
                return Err(NelOptionsError::InvalidReportingEndpointName(
                    name.to_string(),
                ));
            }

            let lowered = name.to_ascii_lowercase();
            if !seen.insert(lowered) {
                return Err(NelOptionsError::DuplicateReportingEndpoint(
                    name.to_string(),
                ));
            }

            let url = endpoint.url();

            if url.trim().is_empty() {
                return Err(NelOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }

            let parsed = Url::parse(url)
                .map_err(|_| NelOptionsError::InvalidReportingEndpointUrl(url.to_string()))?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(NelOptionsError::InvalidReportingEndpointUrl(
                    url.to_string(),
                ));
            }
        }

        Ok(())
    }
}

fn valid_endpoint_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

fn format_fraction(value: f32) -> String {
    let mut formatted = format!("{value}");

    if let Some(dot_index) = formatted.find('.') {
        while formatted.ends_with('0') {
            formatted.pop();
        }

        if formatted.len() == dot_index {
            formatted.push('0');
        }
    }

    formatted
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
