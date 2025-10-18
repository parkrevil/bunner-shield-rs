use super::*;
use crate::csrf::CsrfOptionsError;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_secure_cookie_prefix_when_validate_options_then_returns_ok() {
        let executor = Csrf::new(CsrfOptions::new(secret()));

        let result = executor.validate_options();

        assert!(result.is_ok());
    }

    #[test]
    fn given_custom_cookie_without_host_prefix_when_validate_options_then_returns_prefix_error() {
        let executor = Csrf::new(CsrfOptions::new(secret()).cookie_name("csrf-token"));

        let error = executor
            .validate_options()
            .expect_err("expected cookie prefix error");

        assert_eq!(
            error.to_string(),
            CsrfOptionsError::InvalidCookiePrefix.to_string()
        );
    }

    #[test]
    fn given_token_length_outside_range_when_validate_options_then_returns_length_error() {
        let executor = Csrf::new(CsrfOptions::new(secret()).token_length(10));

        let error = executor
            .validate_options()
            .expect_err("expected token length error");

        assert_eq!(
            error.to_string(),
            CsrfOptionsError::InvalidTokenLength {
                requested: 10,
                minimum: 32,
                maximum: 64,
            }
            .to_string()
        );
    }
}

fn secret() -> [u8; 32] {
    [0xAB; 32]
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_options() {
        let options = CsrfOptions::new(secret()).token_length(40);
        let executor = Csrf::new(options);

        let result = executor.options();

        let expected = CsrfOptions::new(secret()).token_length(40);
        assert_eq!(result.cookie_name, expected.cookie_name);
        assert_eq!(result.token_length, expected.token_length);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_valid_configuration_when_execute_then_sets_token_and_cookie_headers() {
        let secret = secret();
        let options = CsrfOptions::new(secret);
        let expected_service = HmacCsrfService::new(secret);
        let expected_token = expected_service
            .issue(64)
            .expect("expected issue to succeed");
        let executor = Csrf::new(options);
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(result.get("X-CSRF-Token"), Some(&expected_token.clone()));
        assert_eq!(
            result.get("Set-Cookie"),
            Some(&format!(
                "__Host-csrf-token={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                expected_token
            ))
        );
    }

    #[test]
    fn given_custom_cookie_name_when_execute_then_sets_cookie_with_custom_prefix() {
        let secret = secret();
        let options = CsrfOptions::new(secret).cookie_name("__Host-custom-csrf");
        let expected_service = HmacCsrfService::new(secret);
        let expected_token = expected_service
            .issue(64)
            .expect("expected issue to succeed");
        let executor = Csrf::new(options);
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let cookie = headers
            .into_result()
            .get("Set-Cookie")
            .expect("expected set-cookie header")
            .to_string();
        assert!(cookie.starts_with("__Host-custom-csrf="));
        assert!(cookie.contains(&expected_token));
    }

    #[test]
    fn given_invalid_token_length_when_execute_then_returns_token_generation_error() {
        let options = CsrfOptions::new(secret()).token_length(70);
        let mut headers = common::normalized_headers_from(&[]);
        let executor = Csrf::new(options);

        let error = executor
            .execute(&mut headers)
            .expect_err("expected token generation error");

        let expected = CsrfError::TokenGeneration(CsrfTokenError::InvalidTokenLength(70));
        assert_eq!(error.to_string(), expected.to_string());
    }

    #[test]
    fn given_zero_token_length_when_execute_then_returns_token_generation_error() {
        let options = CsrfOptions::new(secret()).token_length(0);
        let mut headers = common::normalized_headers_from(&[]);
        let executor = Csrf::new(options);

        let error = executor
            .execute(&mut headers)
            .expect_err("expected token generation error");

        let expected = CsrfError::TokenGeneration(CsrfTokenError::InvalidTokenLength(0));
        assert_eq!(error.to_string(), expected.to_string());
    }
}
