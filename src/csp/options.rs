use crate::executor::FeatureOptions;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspReportGroup {
    name: String,
    endpoint: String,
    max_age: u64,
}

impl CspReportGroup {
    pub fn new<'a>(name: impl Into<Cow<'a, str>>, endpoint: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name: name.into().into_owned(),
            endpoint: endpoint.into().into_owned(),
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

    pub fn directive<'a>(
        mut self,
        name: impl Into<Cow<'a, str>>,
        value: impl Into<Cow<'a, str>>,
    ) -> Self {
        self.directives
            .push((name.into().into_owned(), value.into().into_owned()));
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
        let mut chars = name.chars();

        match chars.next() {
            Some(first) if first.is_ascii_lowercase() => {}
            _ => return false,
        }

        chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
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

            Self::validate_directive_value(value)?;
        }

        if self.report_only && self.report_group.is_none() {
            return Err(CspOptionsError::ReportOnlyMissingGroup);
        }

        if let Some(group) = &self.report_group {
            if Self::has_invalid_header_text(&group.name) || group.name.trim().is_empty() {
                return Err(CspOptionsError::InvalidReportGroup);
            }

            if Self::has_invalid_header_text(&group.endpoint) || group.endpoint.trim().is_empty() {
                return Err(CspOptionsError::InvalidReportGroup);
            }
        }

        Ok(())
    }
}

impl CspOptions {
    fn has_invalid_header_text(value: &str) -> bool {
        value.contains(['\r', '\n'])
    }

    fn validate_directive_value(value: &str) -> Result<(), CspOptionsError> {
        if value.trim().is_empty() {
            return Err(CspOptionsError::InvalidDirectiveValue);
        }

        if Self::has_invalid_header_text(value) {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        for token in value.split_whitespace() {
            Self::validate_token(token)?;
        }

        Ok(())
    }

    fn validate_token(token: &str) -> Result<(), CspOptionsError> {
        if token.is_empty() {
            return Err(CspOptionsError::InvalidDirectiveValue);
        }

        if let Some(rest) = token.strip_prefix("'nonce-") {
            return Self::validate_nonce(rest);
        }

        if let Some(rest) = token.strip_prefix("'sha256-") {
            return Self::validate_hash(rest, 44);
        }

        if let Some(rest) = token.strip_prefix("'sha384-") {
            return Self::validate_hash(rest, 64);
        }

        if let Some(rest) = token.strip_prefix("'sha512-") {
            return Self::validate_hash(rest, 88);
        }

        if token.starts_with('"') || token.ends_with('"') {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        if token.starts_with('\'') && !token.ends_with('\'') {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        if token.chars().any(|ch| ch.is_control()) {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        Ok(())
    }

    fn validate_nonce(rest: &str) -> Result<(), CspOptionsError> {
        let encoded = rest
            .strip_suffix('\'')
            .ok_or(CspOptionsError::InvalidNonce)?;

        if encoded.len() < 22 {
            return Err(CspOptionsError::InvalidNonce);
        }

        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
        {
            return Err(CspOptionsError::InvalidNonce);
        }

        Ok(())
    }

    fn validate_hash(rest: &str, expected_len: usize) -> Result<(), CspOptionsError> {
        let encoded = rest
            .strip_suffix('\'')
            .ok_or(CspOptionsError::InvalidHash)?;

        if encoded.len() != expected_len {
            return Err(CspOptionsError::InvalidHash);
        }

        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
        {
            return Err(CspOptionsError::InvalidHash);
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
    #[error("invalid directive token")]
    InvalidDirectiveToken,
    #[error("invalid nonce source expression")]
    InvalidNonce,
    #[error("invalid hash source expression")]
    InvalidHash,
    #[error("report-only mode requires report group")]
    ReportOnlyMissingGroup,
    #[error("invalid report group")]
    InvalidReportGroup,
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
