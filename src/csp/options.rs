use crate::feature::FeatureOptions;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspReportGroup {
    name: String,
    endpoint: String,
    max_age: u64,
}

impl CspReportGroup {
    pub fn new(name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            max_age: 10_886_400,
        }
    }

    pub fn to_header_value(&self) -> String {
        format!(
            "{{\"group\":\"{}\",\"max_age\":{},\"endpoints\":[{{\"url\":\"{}\"}}]}}",
            self.name, self.max_age, self.endpoint
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CspOptions {
    pub(crate) directives: Vec<(String, String)>,
    pub(crate) report_only: bool,
    pub(crate) report_group: Option<CspReportGroup>,
}

impl CspOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn directive(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.directives.push((name.into(), value.into()));
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

    fn is_valid_directive_name(name: &str) -> bool {
        !name.trim().is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    }

    fn contains_invalid_token(value: &str) -> bool {
        value.contains(['\r', '\n']) || value.trim().is_empty()
    }

    pub fn serialize(&self) -> String {
        self.directives
            .iter()
            .map(|(name, value)| format!("{} {}", name, value))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl FeatureOptions for CspOptions {
    type Error = CspOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.directives.is_empty() {
            return Err(CspOptionsError::MissingDirectives);
        }

        for (name, value) in &self.directives {
            if !Self::is_valid_directive_name(name) {
                return Err(CspOptionsError::InvalidDirectiveName);
            }

            if Self::contains_invalid_token(value) {
                return Err(CspOptionsError::InvalidDirectiveValue);
            }
        }

        if self.report_only && self.report_group.is_none() {
            return Err(CspOptionsError::ReportOnlyMissingGroup);
        }

        if let Some(group) = &self.report_group {
            if Self::contains_invalid_token(&group.name) || group.name.trim().is_empty() {
                return Err(CspOptionsError::InvalidReportGroup);
            }

            if Self::contains_invalid_token(&group.endpoint) || group.endpoint.trim().is_empty() {
                return Err(CspOptionsError::InvalidReportGroup);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CspOptionsError {
    #[error("missing directives")]
    MissingDirectives,
    #[error("invalid directive name")]
    InvalidDirectiveName,
    #[error("invalid directive value")]
    InvalidDirectiveValue,
    #[error("report-only mode requires report group")]
    ReportOnlyMissingGroup,
    #[error("invalid report group")]
    InvalidReportGroup,
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
