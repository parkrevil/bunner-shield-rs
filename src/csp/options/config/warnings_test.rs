use super::*;

mod max {
    use super::*;

    #[test]
    fn given_info_levels_when_max_then_returns_info() {
        assert_eq!(
            CspWarningSeverity::Info.max(CspWarningSeverity::Info),
            CspWarningSeverity::Info
        );
        assert_eq!(
            CspWarningSeverity::Warning.max(CspWarningSeverity::Info),
            CspWarningSeverity::Warning
        );
    }
}

mod info {
    use super::*;

    #[test]
    fn given_warning_constructor_when_info_then_sets_info_severity() {
        let info = CspOptionsWarning::info(CspOptionsWarningKind::WeakWorkerSrcFallback);
        assert!(matches!(info.severity, CspWarningSeverity::Info));
    }
}

mod warning {
    use super::*;

    #[test]
    fn given_warning_constructor_when_warning_then_sets_warning_severity() {
        let warning = CspOptionsWarning::warning(
            CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
        );
        assert!(matches!(warning.severity, CspWarningSeverity::Warning));
    }
}

mod critical {
    use super::*;

    #[test]
    fn given_warning_constructor_when_critical_then_sets_critical_severity() {
        let critical = CspOptionsWarning::critical(CspOptionsWarningKind::MissingWorkerSrcFallback);
        assert!(matches!(critical.severity, CspWarningSeverity::Critical));
    }
}
