use crate::executor::{FeatureOptions, ReportContext};
use thiserror::Error;

const DEFAULT_MAX_AGE: u64 = 2_592_000; // 30 days

#[derive(Debug, Clone, PartialEq)]
pub struct NelOptions {
    pub(crate) report_to: String,
    pub(crate) max_age: u64,
    pub(crate) include_subdomains: bool,
    pub(crate) failure_fraction: Option<f32>,
    pub(crate) success_fraction: Option<f32>,
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
}

impl Default for NelOptions {
    fn default() -> Self {
        Self {
            report_to: "default".to_string(),
            max_age: DEFAULT_MAX_AGE,
            include_subdomains: false,
            failure_fraction: None,
            success_fraction: None,
        }
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
