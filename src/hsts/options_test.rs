use super::*;

mod new {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_sets_preload_minimum_max_age() {
        let options = HstsOptions::new();

        assert_eq!(options.max_age, 31_536_000);
        assert!(!options.include_subdomains);
        assert!(!options.preload);
    }
}

mod max_age {
    use super::*;

    #[test]
    fn given_custom_seconds_when_max_age_then_updates_max_age_field() {
        let options = HstsOptions::new().max_age(120);

        assert_eq!(options.max_age, 120);
    }
}

mod include_subdomains {
    use super::*;

    #[test]
    fn given_include_subdomains_when_include_subdomains_then_sets_flag_true() {
        let options = HstsOptions::new().include_subdomains();

        assert!(options.include_subdomains);
    }
}

mod preload {
    use super::*;

    #[test]
    fn given_preload_when_preload_then_sets_preload_flag_true() {
        let options = HstsOptions::new().preload();

        assert!(options.preload);
    }
}

mod header_value {
    use super::*;

    #[test]
    fn given_all_flags_when_header_value_then_returns_composed_directive() {
        let options = HstsOptions::new()
            .max_age(63_072_000)
            .include_subdomains()
            .preload();

        let value = options.header_value();

        assert_eq!(value, "max-age=63072000; includeSubDomains; preload");
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_zero_max_age_when_validate_then_returns_invalid_max_age_error() {
        let options = HstsOptions::new().max_age(0);

        let error = options
            .validate()
            .expect_err("expected invalid max age error");

        assert_eq!(error, HstsOptionsError::InvalidMaxAge);
    }

    #[test]
    fn given_preload_without_subdomains_when_validate_then_returns_include_subdomains_error() {
        let options = HstsOptions::new().preload();

        let error = options
            .validate()
            .expect_err("expected include subdomains preload error");

        assert_eq!(error, HstsOptionsError::PreloadRequiresIncludeSubdomains);
    }

    #[test]
    fn given_preload_with_short_max_age_when_validate_then_returns_long_max_age_error() {
        let options = HstsOptions::new()
            .include_subdomains()
            .max_age(10)
            .preload();

        let error = options
            .validate()
            .expect_err("expected preload long max age error");

        assert_eq!(error, HstsOptionsError::PreloadRequiresLongMaxAge);
    }

    #[test]
    fn given_valid_preload_configuration_when_validate_then_returns_ok() {
        let options = HstsOptions::new()
            .include_subdomains()
            .max_age(40_000_000)
            .preload();

        let result = options.validate();

        assert!(result.is_ok());
    }
}
