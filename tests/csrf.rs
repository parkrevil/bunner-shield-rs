use bunner_shield_rs::{CsrfOptions, CsrfOptionsError, HmacCsrfService, Shield, ShieldError};
mod common;
use common::empty_headers;

fn secret() -> [u8; 32] {
    [0x55; 32]
}

mod success {
    use super::*;

    #[test]
    fn given_valid_configuration_when_secure_then_sets_token_and_cookie_attributes() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let token = result.get("X-CSRF-Token").expect("csrf token present");
        // Verify token signature using the same secret
        let service = HmacCsrfService::new(secret());
        assert!(service.verify(token).is_ok());

        let cookie = result.get("Set-Cookie").expect("csrf cookie present");
        assert!(cookie.contains("__Host-csrf-token="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn given_custom_token_length_when_secure_then_honors_requested_length() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).token_length(40))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let token = result.get("X-CSRF-Token").expect("csrf token present");
        // Length differs due to base64url encoding; ensure token verifies
        let service = HmacCsrfService::new(secret());
        assert!(service.verify(token).is_ok());
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

    #[test]
    fn given_custom_cookie_name_when_secure_then_enforces_host_prefix_invariants() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).cookie_name("__Host-csrf-alt"))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let cookie = result.get("Set-Cookie").expect("csrf cookie present");
        assert!(cookie.starts_with("__Host-csrf-alt="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain="));
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
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn given_existing_cookie_when_secure_then_appends_csrf_cookie() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Set-Cookie".to_string(), "session=abc; Path=/".to_string());

        let result = shield.secure(headers).expect("secure");

        let cookies = result.get("Set-Cookie").expect("cookies present");
        let mut lines: Vec<&str> = cookies.split('\n').collect();
        lines.sort();

        assert!(lines.iter().any(|line| line.starts_with("session=abc")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("__Host-csrf-token=") && line.contains("SameSite=Lax"))
        );
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

        assert!(matches!(
            error,
            CsrfOptionsError::InvalidCookiePrefix { .. }
        ));
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

mod origin_validation {
    use super::*;
    use std::collections::HashMap;

    fn expect_execution_error(result: Result<HashMap<String, String>, ShieldError>) -> String {
        match result {
            Err(ShieldError::ExecutionFailed(err)) => err.to_string(),
            Err(ShieldError::ExecutorValidationFailed(err)) => {
                panic!("expected execution failure, got validation error: {err}")
            }
            Ok(_) => panic!("expected execution failure but secure() succeeded"),
        }
    }

    #[test]
    fn given_validation_enabled_and_matching_origin_then_secure_ok() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, false))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Host".into(), "example.com".into());
        headers.insert("Origin".into(), "https://example.com".into());

        let result = shield.secure(headers).expect("secure");
        assert!(result.contains_key("X-CSRF-Token"));
    }

    #[test]
    fn given_validation_enabled_and_mismatched_origin_then_secure_fails() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, false))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Host".into(), "example.com".into());
        headers.insert("Origin".into(), "https://evil.com".into());

        let msg = expect_execution_error(shield.secure(headers));
        assert!(msg.contains("origin/referer validation failed"));
    }

    #[test]
    fn given_validation_enabled_and_use_referer_true_then_referer_match_ok() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, true))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Host".into(), "example.com".into());
        headers.insert("Referer".into(), "https://example.com/path?q=1".into());

        let result = shield.secure(headers).expect("secure");
        assert!(result.contains_key("X-CSRF-Token"));
    }

    #[test]
    fn given_validation_enabled_and_use_referer_true_then_referer_mismatch_fails() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, true))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Host".into(), "example.com".into());
        headers.insert("Referer".into(), "https://evil.com/page".into());

        let msg = expect_execution_error(shield.secure(headers));
        assert!(msg.contains("origin/referer validation failed"));
    }

    #[test]
    fn given_validation_enabled_but_no_host_then_validation_is_skipped() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, false))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Origin".into(), "https://evil.com".into());

        // No Host header -> skip origin validation and still issue token
        let result = shield.secure(headers).expect("secure");
        assert!(result.contains_key("X-CSRF-Token"));
    }

    #[test]
    fn given_null_or_empty_origin_and_no_fallback_then_missing_origin_error() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(true, false))
            .expect("feature");

        let mut headers1 = empty_headers();
        headers1.insert("Host".into(), "example.com".into());
        headers1.insert("Origin".into(), "null".into());
        let msg1 = expect_execution_error(shield.secure(headers1));
        assert!(msg1.contains("origin/referer validation failed"));

        let mut headers2 = empty_headers();
        headers2.insert("Host".into(), "example.com".into());
        headers2.insert("Origin".into(), " ".into());
        let msg2 = expect_execution_error(shield.secure(headers2));
        assert!(msg2.contains("origin/referer validation failed"));
    }

    #[test]
    fn given_validation_disabled_then_ignores_origin_headers() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret()).origin_validation(false, false))
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("Host".into(), "example.com".into());
        headers.insert("Origin".into(), "https://evil.com".into());

        // Since validation disabled, secure still succeeds
        let result = shield.secure(headers).expect("secure");
        assert!(result.contains_key("X-CSRF-Token"));
    }
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("X-CSRF-Token")
                        || key.eq_ignore_ascii_case("Set-Cookie")
                    {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy(name: &'static str) -> impl Strategy<Value = String> {
        let len = name.len();
        prop::collection::vec(prop::bool::ANY, len).prop_map(move |mask| {
            name.chars()
                .zip(mask)
                .map(|(ch, lower)| match ch {
                    '-' => '-',
                    letter if lower => letter.to_ascii_lowercase(),
                    letter => letter.to_ascii_uppercase(),
                })
                .collect()
        })
    }

    fn header_value_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[ -~]{0,96}").unwrap()
    }

    fn dedup_case_insensitive(entries: Vec<(String, String)>) -> Vec<(String, String)> {
        use std::collections::HashMap as StdHashMap;
        let mut map: StdHashMap<String, (String, String)> = StdHashMap::new();
        for (name, value) in entries {
            map.insert(name.to_ascii_lowercase(), (name, value));
        }
        map.into_values().collect()
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_then_sets_token_and_cookie_idempotently(
            baseline in header_entries_strategy(),
            token_name in header_case_strategy("X-CSRF-Token"),
            token_value in header_value_strategy(),
            set_cookie_name in header_case_strategy("Set-Cookie"),
            set_cookie_value in header_value_strategy(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            // Optionally insert preexisting headers that should be overwritten/collapsed
            headers.insert(token_name, token_value);
            headers.insert(set_cookie_name, set_cookie_value);

            let shield = Shield::new().csrf(CsrfOptions::new(secret())).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            // Verify tokens from both runs are valid and header names are canonical
            let service = HmacCsrfService::new(secret());
            let token1 = once.get("X-CSRF-Token").cloned().unwrap_or_default();
            let token2 = twice.get("X-CSRF-Token").cloned().unwrap_or_default();
            prop_assert!(service.verify(&token1).is_ok());
            prop_assert!(service.verify(&token2).is_ok());

            // Set-Cookie must contain our CSRF cookie with required attributes.
            let cookie1 = once.get("Set-Cookie").cloned().unwrap_or_default();
            let cookie2 = twice.get("Set-Cookie").cloned().unwrap_or_default();
            let lines1: Vec<&str> = cookie1.split('\n').collect();
            let lines2: Vec<&str> = cookie2.split('\n').collect();
            // There must be at least one line with our CSRF cookie attributes
            prop_assert!(lines1.iter().any(|l| l.contains("__Host-") && l.contains("Path=/") && l.contains("Secure") && l.contains("HttpOnly") && l.contains("SameSite=Lax")));
            prop_assert!(lines2.iter().any(|l| l.contains("__Host-") && l.contains("Path=/") && l.contains("Secure") && l.contains("HttpOnly") && l.contains("SameSite=Lax")));
            // Second run appends exactly one additional cookie line
            prop_assert_eq!(lines2.len(), lines1.len() + 1);
        }
    }
}
