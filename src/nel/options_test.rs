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
            .success_fraction(0.25);

        assert!(options.validate().is_ok());
    }
}
