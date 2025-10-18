use super::*;
use crate::executor::FeatureExecutor;
use crate::hsts::HstsOptionsError;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_valid_options_when_validate_options_then_returns_ok() {
        let executor = Hsts::new(HstsOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }

    #[test]
    fn given_zero_max_age_when_validate_options_then_returns_invalid_max_age_error() {
        let executor = Hsts::new(HstsOptions::new().max_age(0));

        let error = executor
            .validate_options()
            .expect_err("expected invalid max-age error");

        assert_eq!(
            error.to_string(),
            HstsOptionsError::InvalidMaxAge.to_string()
        );
    }
}

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = HstsOptions::new().include_subdomains();
        let executor = Hsts::new(options);

        let result = executor.options();

        let expected = HstsOptions::new().include_subdomains();
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_hsts_header_with_cached_value() {
        let executor = Hsts::new(HstsOptions::new().max_age(10));
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Strict-Transport-Security"),
            Some(&"max-age=10".to_string())
        );
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = Hsts::new(HstsOptions::new().include_subdomains().max_age(50));
        let mut first_headers = common::normalized_headers_from(&[]);
        let mut second_headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut first_headers)
            .expect("first execute should succeed");
        executor
            .execute(&mut second_headers)
            .expect("second execute should succeed");

        let first = first_headers.into_result();
        let second = second_headers.into_result();
        assert_eq!(
            first.get("Strict-Transport-Security"),
            Some(&"max-age=50; includeSubDomains".to_string())
        );
        assert_eq!(
            second.get("Strict-Transport-Security"),
            Some(&"max-age=50; includeSubDomains".to_string())
        );
    }
}
