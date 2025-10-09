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
            options.serialize(),
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
}

mod report_group {
    use super::*;

    #[test]
    fn given_valid_group_when_to_header_value_then_returns_serialized_json() {
        let group = CspReportGroup::new("default", "https://reports.example.com");

        let header_value = group.to_header_value();

        assert_eq!(
            header_value,
            "{\"group\":\"default\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://reports.example.com\"}]}"
        );
    }
}
