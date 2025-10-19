use super::*;
use crate::CspSource;
use crate::csp::options::{CspOptionsWarningKind, CspWarningSeverity};

mod validate_with_warnings {
    use super::*;

    #[test]
    fn given_no_worker_script_or_default_when_validate_with_warnings_then_emits_missing_worker_fallback_critical()
     {
        let options = CspOptions::new().base_uri([CspSource::SelfKeyword]);
        let warnings = validate_with_warnings(&options).expect("validation should succeed");
        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Critical,
                kind: CspOptionsWarningKind::MissingWorkerSrcFallback,
            }
        )));
    }

    #[test]
    fn given_permissive_default_only_when_validate_with_warnings_then_emits_weak_worker_fallback_warning()
     {
        let options = CspOptions::new().default_src([CspSource::Wildcard]);
        let warnings = validate_with_warnings(&options).expect("validation should succeed");
        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Warning,
                kind: CspOptionsWarningKind::WeakWorkerSrcFallback,
            }
        )));
    }
}
