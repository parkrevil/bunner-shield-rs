use bunner_shield_rs::{
    SameSiteOptions, SameSiteOptionsError, SameSitePolicy, Shield, ShieldError,
};
use std::collections::HashMap;
mod common;
use common::empty_headers;

fn with_cookie(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Set-Cookie".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_cookie_without_attributes_when_secure_then_sets_defaults() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let result = shield.secure(with_cookie("session=abc")).expect("secure");

        assert_eq!(
            result.get("Set-Cookie").map(String::as_str),
            Some("session=abc; Secure; HttpOnly; SameSite=Lax")
        );
    }

    #[test]
    fn given_cookie_with_attributes_when_secure_then_overrides_policy_flags() {
        let options = SameSiteOptions::new()
            .http_only(false)
            .same_site(SameSitePolicy::Strict);
        let shield = Shield::new().same_site(options).expect("feature");

        let result = shield
            .secure(with_cookie("session=abc; SameSite=None; Secure"))
            .expect("secure");

        assert_eq!(
            result.get("Set-Cookie").map(String::as_str),
            Some("session=abc; Secure; SameSite=Strict")
        );
    }

    #[test]
    fn given_same_site_none_with_secure_when_secure_then_sets_none_policy() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new().same_site(SameSitePolicy::None))
            .expect("feature");

        let result = shield
            .secure(with_cookie("session=abc; Path=/"))
            .expect("secure");

        assert_eq!(
            result.get("Set-Cookie").map(String::as_str),
            Some("session=abc; Path=/; Secure; HttpOnly; SameSite=None")
        );
    }

    #[test]
    fn given_request_without_cookie_when_secure_then_leaves_headers_untouched() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert!(result.is_empty());
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_cookie_with_custom_attributes_when_secure_then_preserves_unrelated_pairs() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let mut headers = with_cookie("session=abc; Path=/; Domain=example.com");
        headers.insert("X-Other".to_string(), "value".to_string());

        let result = shield.secure(headers).expect("secure");

        let cookie = result.get("Set-Cookie").expect("cookie present");
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Domain=example.com"));
        assert!(cookie.contains("SameSite=Lax"));
        assert_eq!(result.get("X-Other").map(String::as_str), Some("value"));
    }

    #[test]
    fn given_lowercase_set_cookie_key_when_secure_then_emits_canonical_header() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert("set-cookie".to_string(), "session=abc".to_string());

        let result = shield.secure(headers).expect("secure");

        assert!(result.contains_key("Set-Cookie"));
        assert!(!result.contains_key("set-cookie"));
        let cookie = result.get("Set-Cookie").expect("cookie present");
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn given_host_prefixed_cookie_when_secure_then_retains_required_attributes() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let result = shield
            .secure(with_cookie("__Host-session=abc; Path=/"))
            .expect("secure");

        let cookie = result.get("Set-Cookie").expect("cookie present");
        assert!(cookie.starts_with("__Host-session="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn given_multiple_cookies_when_secure_then_upgrades_each_entry() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let mut headers = empty_headers();
        headers.insert(
            "Set-Cookie".to_string(),
            "session=abc; Path=/\ntracking=1".to_string(),
        );

        let result = shield.secure(headers).expect("secure");

        let cookies = result.get("Set-Cookie").expect("cookies present");
        let lines: Vec<&str> = cookies.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.contains("SameSite=Lax")));
        assert!(lines.iter().all(|line| line.contains("Secure")));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> SameSiteOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<SameSiteOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_none_without_secure_when_add_feature_then_returns_validation_error() {
        let options = SameSiteOptions::new()
            .secure(false)
            .same_site(SameSitePolicy::None);

        let error = expect_validation_error(Shield::new().same_site(options));

        assert!(matches!(
            error,
            SameSiteOptionsError::SameSiteNoneRequiresSecure
        ));
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
                    if key.eq_ignore_ascii_case("Set-Cookie") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn set_cookie_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Set-Cookie".len()).prop_map(|mask| {
            "Set-Cookie"
                .chars()
                .zip(mask)
                .map(|(ch, lower)| match ch {
                    '-' => '-',
                    letter if lower => letter.to_ascii_lowercase(),
                    letter => letter.to_ascii_uppercase(),
                })
                .collect()
        })
    }

    fn cookie_value_strategy() -> impl Strategy<Value = String> {
        // Single cookie per line, avoid newlines here; executor splits by newlines already.
        prop::string::string_regex("[A-Za-z0-9_=; ,.\t:/-]{1,128}").unwrap()
    }

    // Remove duplicate header names case-insensitively for baseline expectations.
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
        fn given_any_headers_and_optional_existing_cookie_when_secure_then_idempotent_and_non_destructive(
            baseline in header_entries_strategy(),
            cookie_name in set_cookie_case_strategy(),
            cookie_value in cookie_value_strategy(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            headers.insert(cookie_name.clone(), cookie_value.clone());

            let shield = Shield::new().same_site(SameSiteOptions::new()).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            // Build expected: baseline plus exactly one canonical Set-Cookie with upgraded flags.
            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            let result_cookie = once.get("Set-Cookie").cloned().unwrap_or_default();
            // Ensure policy attributes are present and not duplicated across runs.
            prop_assert!(result_cookie.contains("SameSite="));
            prop_assert!(result_cookie.contains("Secure"));
            prop_assert!(result_cookie.contains("HttpOnly"));
            expected.insert("Set-Cookie".to_string(), result_cookie);

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_set_cookie_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (set_cookie_case_strategy(), set_cookie_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes_set_cookie(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_set_cookie_cases_strategy(),
            values in (cookie_value_strategy(), cookie_value_strategy()),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new().same_site(SameSiteOptions::new()).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            // Expect a single canonical Set-Cookie header with upgraded flags
            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            let cookie = once.get("Set-Cookie").cloned().unwrap_or_default();
            prop_assert!(cookie.contains("SameSite="));
            prop_assert!(cookie.contains("Secure"));
            expected.insert("Set-Cookie".to_string(), cookie);

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
