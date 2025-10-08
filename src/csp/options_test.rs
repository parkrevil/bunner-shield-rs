use super::*;

mod validate {
    use super::*;

    #[test]
    fn given_minimum_directives_when_validate_then_returns_policy() {
        let validated = CspOptions::new()
            .with_directive("default-src", "'self'")
            .with_directive("base-uri", "'none'")
            .with_directive("frame-ancestors", "'none'")
            .validate()
            .expect("policy");

        assert!(!validated.report_only);
        assert!(validated.report_group.is_none());
        assert_eq!(
            validated.serialize(),
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn given_uppercase_directive_when_validate_then_returns_error() {
        let options = CspOptions::new().with_directive("Default-Src", "'self'");

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidDirectiveName)));
    }

    #[test]
    fn given_report_only_without_group_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .with_directive("default-src", "'self'")
            .enable_report_only();

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
            .with_directive("default-src", "'self'")
            .with_report_group(group);

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
