use super::*;
use crate::executor::PolicyMode;

mod default_src {
    use super::*;

    #[test]
    fn given_sources_with_duplicates_when_default_src_then_stores_unique_sources() {
        let options = CspOptions::new().default_src([
            CspSource::SelfKeyword,
            CspSource::SelfKeyword,
            CspSource::Wildcard,
        ]);

        assert_eq!(
            options.directives,
            vec![("default-src".to_string(), "'self' *".to_string())]
        );
    }
}

mod add_source_behavior {
    use super::*;

    #[test]
    fn given_blank_source_when_add_source_then_ignores_entry() {
        let options = CspOptions::new().add_source(CspDirective::ScriptSrc, "   ");
        assert!(options.directives.is_empty());
    }
}

mod flags_and_misc_directives {
    use super::*;

    #[test]
    fn given_upgrade_and_block_flags_when_set_then_present_in_header() {
        let header = CspOptions::new()
            .upgrade_insecure_requests()
            .block_all_mixed_content()
            .header_value();
        assert!(header.contains("upgrade-insecure-requests"));
    }
}

mod report_only {
    use super::*;

    #[test]
    fn given_report_only_when_invoked_then_sets_mode() {
        let options = CspOptions::new().report_only();

        assert_eq!(options.mode(), PolicyMode::ReportOnly);
    }

    #[test]
    fn given_report_only_when_chained_then_preserves_other_configuration() {
        let options = CspOptions::new()
            .report_only()
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(options.mode(), PolicyMode::ReportOnly);
        assert_eq!(
            options.directives,
            vec![("default-src".to_string(), "'self'".to_string())]
        );
    }
}
