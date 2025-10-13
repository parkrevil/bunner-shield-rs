use super::*;
use crate::executor::FeatureOptions;

mod validate {
    use super::*;

    #[test]
    fn given_minimum_directives_when_validate_then_returns_policy() {
        let options = CspOptions::new()
            .directive("default-src", "'self'")
            .directive("base-uri", "'none'")
            .directive("frame-ancestors", "'none'");

        options.validate().expect("policy");

        assert!(!options.report_only);
        assert!(options.report_group.is_none());
        assert_eq!(
            options.header_value(),
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn given_uppercase_directive_when_validate_then_returns_error() {
        let options = CspOptions::new().directive("Default-Src", "'self'");

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidDirectiveName)));
    }

    #[test]
    fn given_report_only_without_group_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .directive("default-src", "'self'")
            .report_only();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::ReportOnlyMissingGroup)
        ));
    }

    #[test]
    fn given_invalid_group_when_validate_then_returns_error() {
        let group = CspReportGroup::new("", "https://reports.example.com");
        let options = CspOptions::new()
            .directive("default-src", "'self'")
            .report_group(group);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidReportGroup)));
    }

    #[test]
    fn given_valid_nonce_when_validate_then_accepts_directive() {
        let options = CspOptions::new()
            .directive("script-src", "'nonce-dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU='")
            .directive("default-src", "'self'");

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_invalid_nonce_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .directive("script-src", "'nonce-@@@@'")
            .directive("default-src", "'self'");

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidNonce)));
    }

    #[test]
    fn given_invalid_hash_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .directive("script-src", "'sha256-short'")
            .directive("default-src", "'self'");

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidHash)));
    }

    #[test]
    fn given_control_character_when_validate_then_returns_error() {
        let options = CspOptions::new().directive("default-src", "'self'\nscript");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidDirectiveToken)
        ));
    }
}

mod helpers {
    use super::*;

    #[test]
    fn given_nonce_helper_when_header_value_then_includes_trimmed_token() {
        let options = CspOptions::new()
            .script_src_nonce(" 'dGVzdE5vbmNlVmFsdWU=' ")
            .directive("default-src", "'self'");

        assert_eq!(
            options.header_value(),
            "script-src 'nonce-dGVzdE5vbmNlVmFsdWU='; default-src 'self'"
        );
    }

    #[test]
    fn given_duplicate_nonce_helper_when_header_value_then_deduplicates_token() {
        let options = CspOptions::new()
            .script_src_nonce("value")
            .script_src_nonce("value")
            .directive("default-src", "'self'");

        assert_eq!(
            options.header_value(),
            "script-src 'nonce-value'; default-src 'self'"
        );
    }

    #[test]
    fn given_hash_helper_when_header_value_then_includes_prefixed_token() {
        let options = CspOptions::new()
            .script_src_hash(CspHashAlgorithm::Sha384, "abc==")
            .directive("default-src", "'self'");

        assert_eq!(
            options.header_value(),
            "script-src 'sha384-abc=='; default-src 'self'"
        );
    }

    #[test]
    fn given_strict_dynamic_helper_when_header_value_then_adds_once() {
        let options = CspOptions::new()
            .enable_strict_dynamic()
            .enable_strict_dynamic()
            .directive("default-src", "'self'");

        assert_eq!(
            options.header_value(),
            "script-src 'strict-dynamic'; default-src 'self'"
        );
    }

    #[test]
    fn given_trusted_types_helper_when_header_value_then_sets_directive() {
        let options = CspOptions::new()
            .require_trusted_types_for_scripts()
            .require_trusted_types_for_scripts()
            .directive("default-src", "'self'");

        assert_eq!(
            options.header_value(),
            "require-trusted-types-for 'script'; default-src 'self'"
        );
    }
}

mod report_group {
    use super::*;

    #[test]
    fn given_valid_group_when_header_value_then_returns_serialized_json() {
        let group = CspReportGroup::new("default", "https://reports.example.com");

        let header_value = group.header_value();

        assert_eq!(
            header_value,
            "{\"group\":\"default\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://reports.example.com\"}]}"
        );
    }
}
