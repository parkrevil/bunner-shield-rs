#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspOptionsWarning {
    pub severity: CspWarningSeverity,
    pub kind: CspOptionsWarningKind,
}

impl CspOptionsWarning {
    pub(crate) fn info(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Info,
            kind,
        }
    }

    pub(crate) fn warning(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Warning,
            kind,
        }
    }

    pub(crate) fn critical(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Critical,
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspWarningSeverity {
    Info,
    Warning,
    Critical,
}

impl CspWarningSeverity {
    pub(crate) fn max(self, other: Self) -> Self {
        use CspWarningSeverity::*;

        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Warning, _) | (_, Warning) => Warning,
            _ => Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspOptionsWarningKind {
    MissingWorkerSrcFallback,
    WeakWorkerSrcFallback,
    UpgradeInsecureRequestsWithoutBlockAllMixedContent,
    BlockAllMixedContentWithoutUpgradeInsecureRequests,
    RiskySchemes {
        directive: String,
        schemes: Vec<String>,
    },
}

#[cfg(test)]
#[path = "warnings_test.rs"]
mod warnings_test;
