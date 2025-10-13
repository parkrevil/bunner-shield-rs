use super::*;
use crate::executor::FeatureOptions;

mod validate {
    use super::*;

    #[test]
    fn given_valid_defaults_when_validate_then_returns_ok() {
        let options = HstsOptions::new();

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_zero_max_age_when_validate_then_returns_error() {
        let options = HstsOptions::new().max_age(0);

        let result = options.validate();

        assert!(matches!(result, Err(HstsOptionsError::InvalidMaxAge)));
    }

    #[test]
    fn given_preload_without_subdomains_when_validate_then_returns_error() {
        let options = HstsOptions::new().preload();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(HstsOptionsError::PreloadRequiresIncludeSubdomains)
        ));
    }

    #[test]
    fn given_preload_with_short_max_age_when_validate_then_returns_error() {
        let options = HstsOptions::new()
            .max_age(10_000)
            .include_subdomains()
            .preload();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(HstsOptionsError::PreloadRequiresLongMaxAge)
        ));
    }

    #[test]
    fn given_valid_preload_combo_when_validate_then_returns_ok() {
        let options = HstsOptions::new()
            .max_age(31_536_000)
            .include_subdomains()
            .preload();

        let result = options.validate();

        assert!(result.is_ok());
        assert_eq!(
            options.header_value(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }
}
