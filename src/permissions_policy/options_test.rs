use super::{PermissionsPolicyOptions, PermissionsPolicyOptionsError};

mod header_value {
    use super::PermissionsPolicyOptions;

    #[test]
    fn given_policy_when_header_value_then_returns_same_value() {
        let options = PermissionsPolicyOptions::new("geolocation=()");

        assert_eq!(options.header_value(), "geolocation=()");
    }
}

mod validate {
    use super::{PermissionsPolicyOptions, PermissionsPolicyOptionsError};
    use crate::csp::{CspReportGroup, CspReportingEndpoint};
    use crate::executor::FeatureOptions;

    #[test]
    fn given_non_empty_policy_when_validate_then_returns_ok() {
        let options = PermissionsPolicyOptions::new("camera=(self)");

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_empty_policy_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        ));
    }

    #[test]
    fn given_whitespace_policy_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("   ");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        ));
    }

    #[test]
    fn given_report_only_without_group_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("geolocation=()\n").report_only();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::ReportOnlyWithoutGroup)
        ));
    }

    #[test]
    fn given_invalid_endpoint_name_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("geolocation=()")
            .report_group(CspReportGroup::new("pp", "https://example.com/reports"))
            .reporting_endpoint("$invalid", "https://example.com/report-endpoint");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::InvalidReportingEndpointName(
                _
            ))
        ));
    }

    #[test]
    fn given_invalid_endpoint_url_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("geolocation=()")
            .report_group(CspReportGroup::new("pp", "https://example.com/reports"))
            .reporting_endpoint("valid", "http://example.com/report-endpoint");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::InvalidReportingEndpointUrl(
                _
            ))
        ));
    }

    #[test]
    fn given_duplicate_endpoint_names_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("geolocation=()")
            .report_group(CspReportGroup::new("pp", "https://example.com/reports"))
            .reporting_endpoint("duplicate", "https://example.com/report-1")
            .reporting_endpoint("Duplicate", "https://example.com/report-2");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::DuplicateReportingEndpoint(_))
        ));
    }

    #[test]
    fn given_valid_reporting_configuration_when_validate_then_returns_ok() {
        let endpoint =
            CspReportingEndpoint::new("pp-endpoint", "https://example.com/report-endpoint");
        let options = PermissionsPolicyOptions::new("geolocation=()")
            .report_only()
            .report_group(CspReportGroup::new("pp", "https://example.com/reports"))
            .add_reporting_endpoint(endpoint);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
