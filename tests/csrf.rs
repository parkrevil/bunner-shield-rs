use bunner_shield_rs::{CsrfOptions, CsrfOptionsError, Shield, ShieldError};
use std::collections::HashMap;

fn secret() -> [u8; 32] {
    [0x55; 32]
}

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

mod success {
    use super::*;

    fn assert_hex(value: &str, expected_len: usize) {
        assert_eq!(value.len(), expected_len);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn given_valid_configuration_when_secure_then_sets_token_and_cookie_attributes() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let token = result.get("X-CSRF-Token").expect("csrf token present");
        assert_hex(token, 64);

        let cookie = result.get("Set-Cookie").expect("csrf cookie present");
        assert!(cookie.contains("__Host-csrf-token="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn given_custom_token_length_when_secure_then_honors_requested_length() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).token_length(40))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let token = result.get("X-CSRF-Token").expect("csrf token present");
        assert_hex(token, 40);
    }

    #[test]
    fn given_multiple_invocations_when_secure_then_returns_distinct_tokens() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()))
            .expect("feature");

        let first = shield.secure(empty_headers()).expect("secure");
        let second = shield.secure(empty_headers()).expect("secure again");

        let token_one = first.get("X-CSRF-Token").expect("first token");
        let token_two = second.get("X-CSRF-Token").expect("second token");

        assert_ne!(token_one, token_two);
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_cookie_with_existing_attributes_when_secure_then_overrides_policy_flags() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert(
            "Set-Cookie".to_string(),
            "__Host-csrf-token=abc; Path=/; SameSite=None".to_string(),
        );

        let result = shield.secure(headers).expect("secure");

        let cookie = result.get("Set-Cookie").expect("csrf cookie present");
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> CsrfOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<CsrfOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_invalid_cookie_prefix_when_add_feature_then_returns_cookie_prefix_error() {
        let error = expect_validation_error(
            Shield::new().csrf(CsrfOptions::new(secret()).cookie_name("csrf")),
        );

        assert!(matches!(error, CsrfOptionsError::InvalidCookiePrefix));
    }

    #[test]
    fn given_token_length_below_minimum_when_add_feature_then_returns_range_error() {
        let error = expect_validation_error(
            Shield::new().csrf(CsrfOptions::new(secret()).token_length(10)),
        );

        match error {
            CsrfOptionsError::InvalidTokenLength {
                requested,
                minimum,
                maximum,
            } => {
                assert_eq!(requested, 10);
                assert_eq!(minimum, 32);
                assert_eq!(maximum, 64);
            }
            other => panic!("expected invalid token length, got {other:?}"),
        }
    }

    #[test]
    fn given_token_length_above_maximum_when_add_feature_then_returns_range_error() {
        let error = expect_validation_error(
            Shield::new().csrf(CsrfOptions::new(secret()).token_length(128)),
        );

        match error {
            CsrfOptionsError::InvalidTokenLength {
                requested,
                minimum,
                maximum,
            } => {
                assert_eq!(requested, 128);
                assert_eq!(minimum, 32);
                assert_eq!(maximum, 64);
            }
            other => panic!("expected invalid token length, got {other:?}"),
        }
    }
}
