use crate::normalized_headers::NormalizedHeaders;
use std::error::Error as StdError;
use std::mem;
use std::sync::{Arc, Mutex};

pub type Executor = Box<dyn DynFeatureExecutor + 'static>;
pub type ExecutorError = Box<dyn StdError + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Validation,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportEntry {
    pub feature: &'static str,
    pub kind: ReportKind,
    pub severity: ReportSeverity,
    pub message: String,
}

impl ReportEntry {
    pub fn new(
        feature: &'static str,
        kind: ReportKind,
        severity: ReportSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            feature,
            kind,
            severity,
            message: message.into(),
        }
    }

    pub fn validation(
        feature: &'static str,
        severity: ReportSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self::new(feature, ReportKind::Validation, severity, message)
    }

    pub fn runtime(
        feature: &'static str,
        severity: ReportSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self::new(feature, ReportKind::Runtime, severity, message)
    }
}

#[derive(Clone, Default)]
pub struct ReportContext {
    inner: Arc<ReportContextInner>,
}

impl ReportContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, entry: ReportEntry) {
        let mut entries = self.inner.entries.lock().expect("report context poisoned");
        entries.push(entry);
    }

    pub fn push_validation(
        &self,
        feature: &'static str,
        severity: ReportSeverity,
        message: impl Into<String>,
    ) {
        self.push(ReportEntry::validation(feature, severity, message));
    }

    pub fn push_validation_info(&self, feature: &'static str, message: impl Into<String>) {
        self.push_validation(feature, ReportSeverity::Info, message);
    }

    pub fn push_validation_warning(&self, feature: &'static str, message: impl Into<String>) {
        self.push_validation(feature, ReportSeverity::Warning, message);
    }

    pub fn push_validation_critical(&self, feature: &'static str, message: impl Into<String>) {
        self.push_validation(feature, ReportSeverity::Critical, message);
    }

    pub fn push_runtime(
        &self,
        feature: &'static str,
        severity: ReportSeverity,
        message: impl Into<String>,
    ) {
        self.push(ReportEntry::runtime(feature, severity, message));
    }

    pub fn push_runtime_info(&self, feature: &'static str, message: impl Into<String>) {
        self.push_runtime(feature, ReportSeverity::Info, message);
    }

    pub fn push_runtime_warning(&self, feature: &'static str, message: impl Into<String>) {
        self.push_runtime(feature, ReportSeverity::Warning, message);
    }

    pub fn push_runtime_critical(&self, feature: &'static str, message: impl Into<String>) {
        self.push_runtime(feature, ReportSeverity::Critical, message);
    }

    pub fn entries(&self) -> Vec<ReportEntry> {
        self.inner
            .entries
            .lock()
            .expect("report context poisoned")
            .clone()
    }

    pub fn drain(&self) -> Vec<ReportEntry> {
        let mut entries = self.inner.entries.lock().expect("report context poisoned");
        mem::take(&mut *entries)
    }
}

struct ReportContextInner {
    entries: Mutex<Vec<ReportEntry>>,
}

impl Default for ReportContextInner {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }
}

pub(crate) trait FeatureExecutor {
    type Options: FeatureOptions;

    fn options(&self) -> &Self::Options;
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError>;
    fn emit_runtime_report(
        &self,
        _context: &ReportContext,
        _headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }
    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError> {
        self.options()
            .validate()
            .map_err(|err| Box::new(err) as ExecutorError)?;
        self.options().emit_validation_reports(context);
        Ok(())
    }
}

pub(crate) trait FeatureOptions {
    type Error: StdError + Send + Sync + 'static;

    fn validate(&self) -> Result<(), Self::Error>;
    fn emit_validation_reports(&self, _context: &ReportContext) {}
}

#[derive(Default)]
pub(crate) struct NoopOptions;

impl FeatureOptions for NoopOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub(crate) trait DynFeatureExecutor {
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError>;
    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError>;
    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError>;
}

impl<T> DynFeatureExecutor for T
where
    T: FeatureExecutor,
{
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        FeatureExecutor::execute(self, headers)
    }

    fn validate_options(&self, context: &ReportContext) -> Result<(), ExecutorError> {
        FeatureExecutor::validate_options(self, context)
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        FeatureExecutor::emit_runtime_report(self, context, headers)
    }
}
