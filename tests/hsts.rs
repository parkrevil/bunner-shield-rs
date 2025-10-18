use bunner_shield_rs::{HstsOptions, HstsOptionsError, Shield, ShieldError};
use std::collections::HashMap;
mod common;
use common::empty_headers;

fn with_hsts(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Strict-Transport-Security".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_uses_one_year_max_age() {
        let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000")
        );
    }

    #[test]
    fn given_include_subdomains_when_secure_then_sets_flagged_header() {
        let shield = Shield::new()
            .hsts(HstsOptions::new().include_subdomains())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
    }

    #[test]
    fn given_preload_configuration_when_secure_then_sets_preload_and_subdomains() {
        let shield = Shield::new()
            .hsts(
                HstsOptions::new()
                    .include_subdomains()
                    .preload()
                    .max_age(31_536_000),
            )
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains; preload")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_expected_policy() {
        let shield = Shield::new()
            .hsts(HstsOptions::new().include_subdomains())
            .expect("feature");

        let result = shield.secure(with_hsts("max-age=0")).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_preserves_them() {
        let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");

        let mut headers = with_hsts("max-age=10");
        headers.insert("Server".to_string(), "api".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("Server").map(String::as_str), Some("api"));
    }

    #[test]
    fn given_existing_header_with_mixed_case_key_when_secure_then_overwrites_canonically() {
        let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");

        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=10".to_string(),
        );

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000")
        );
        assert!(!result.contains_key("strict-transport-security"));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> HstsOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<HstsOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_zero_max_age_when_add_feature_then_returns_invalid_max_age_error() {
        let error = expect_validation_error(Shield::new().hsts(HstsOptions::new().max_age(0)));

        assert!(matches!(error, HstsOptionsError::InvalidMaxAge));
    }

    #[test]
    fn given_preload_without_subdomains_when_add_feature_then_returns_subdomain_error() {
        let error = expect_validation_error(Shield::new().hsts(HstsOptions::new().preload()));

        assert!(matches!(
            error,
            HstsOptionsError::PreloadRequiresIncludeSubdomains
        ));
    }

    #[test]
    fn given_preload_with_short_max_age_when_add_feature_then_returns_long_max_age_error() {
        let options = HstsOptions::new()
            .include_subdomains()
            .preload()
            .max_age(10);

        let error = expect_validation_error(Shield::new().hsts(options));

        assert!(matches!(error, HstsOptionsError::PreloadRequiresLongMaxAge));
    }
}
