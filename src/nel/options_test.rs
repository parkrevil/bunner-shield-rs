use super::*;

mod header_value {
    use super::*;

    #[test]
    fn given_default_options_when_header_value_then_serializes_minimal_object() {
        let options = NelOptions::new();

        assert_eq!(
            options.header_value(),
            "{\"report_to\":\"default\",\"max_age\":2592000}"
        );
    }

    #[test]
    fn given_all_flags_when_header_value_then_includes_optional_fields() {
        let options = NelOptions::new()
            .report_to("primary")
            .max_age(86_400)
            .include_subdomains(true)
            .failure_fraction(0.25)
            .success_fraction(0.75);

        assert_eq!(
            options.header_value(),
            "{\"report_to\":\"primary\",\"max_age\":86400,\"include_subdomains\":true,\"failure_fraction\":0.25,\"success_fraction\":0.75}"
        );
    }
}

mod validation {
    use super::*;

    #[test]
    fn given_empty_report_to_when_validate_then_returns_error() {
        let options = NelOptions::new().report_to("");

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::EmptyReportTo)
        ));
    }

    #[test]
    fn given_zero_max_age_when_validate_then_returns_error() {
        let options = NelOptions::new().max_age(0);

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::InvalidMaxAge)
        ));
    }

    #[test]
    fn given_invalid_failure_fraction_when_validate_then_returns_error() {
        let options = NelOptions::new().failure_fraction(1.5);

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::InvalidFailureFraction(value)) if value == 1.5
        ));
    }

    #[test]
    fn given_invalid_success_fraction_when_validate_then_returns_error() {
        let options = NelOptions::new().success_fraction(-0.1);

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::InvalidSuccessFraction(value)) if value == -0.1
        ));
    }

    #[test]
    fn given_valid_options_when_validate_then_returns_ok() {
        let options = NelOptions::new()
            .report_to("primary")
            .max_age(86_400)
            .include_subdomains(true)
            .failure_fraction(0.5)
            .success_fraction(0.25)
            .reporting_endpoint("default", "https://reports.example.com");

        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_invalid_reporting_endpoint_name_when_validate_then_returns_error() {
        let options =
            NelOptions::new().reporting_endpoint("invalid name", "https://reports.example.com");

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::InvalidReportingEndpointName(name)) if name == "invalid name"
        ));
    }

    #[test]
    fn given_http_reporting_endpoint_url_when_validate_then_returns_error() {
        let options = NelOptions::new().reporting_endpoint("default", "http://reports.example.com");

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::InvalidReportingEndpointUrl(url)) if url == "http://reports.example.com"
        ));
    }

    #[test]
    fn given_duplicate_reporting_endpoint_names_when_validate_then_returns_error() {
        let options = NelOptions::new()
            .reporting_endpoint("DEFAULT", "https://reports.example.com")
            .reporting_endpoint("default", "https://backup.example.com");

        assert!(matches!(
            options.validate(),
            Err(NelOptionsError::DuplicateReportingEndpoint(name)) if name == "default"
        ));
    }
}

mod reporting_headers {
    use super::*;

    #[test]
    fn given_reporting_endpoint_when_report_to_header_value_then_serializes_group() {
        let options = NelOptions::new()
            .report_to("nel")
            .max_age(86_400)
            .reporting_endpoint("default", "https://reports.example.com");

        let value = options.report_to_header_value().expect("value");

        assert!(value.contains("\"group\":\"nel\""));
        assert!(value.contains("\"endpoints\""));
        assert!(value.contains("https://reports.example.com"));
    }

    #[test]
    fn given_reporting_endpoint_when_reporting_endpoints_header_value_then_serializes_header() {
        let options =
            NelOptions::new().reporting_endpoint("default", "https://reports.example.com");

        assert_eq!(
            options.reporting_endpoints_header_value(),
            Some("default=\"https://reports.example.com\"".to_string())
        );
    }
}
