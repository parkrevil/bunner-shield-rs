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
                    if key.eq_ignore_ascii_case("Strict-Transport-Security") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Strict-Transport-Security".len()).prop_map(|mask| {
            "Strict-Transport-Security"
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
        fn given_any_headers_and_optional_existing_when_secure_then_sets_default_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("Strict-Transport-Security".to_string(), "max-age=31536000".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_subdomains_then_sets_flag_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new().hsts(HstsOptions::new().include_subdomains()).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("Strict-Transport-Security".to_string(), "max-age=31536000; includeSubDomains".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_preload_then_sets_flags_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
            max_age in 31_536_000u64..=200_000_000u64,
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let options = HstsOptions::new().include_subdomains().preload().max_age(max_age);
            let shield = Shield::new().hsts(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("Strict-Transport-Security".to_string(), format!("max-age={max_age}; includeSubDomains; preload"));

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_hsts_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (header_case_strategy(), header_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_hsts_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("Strict-Transport-Security".to_string(), "max-age=31536000".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_random_options_when_validate_then_invariants_enforced(
            preload in any::<bool>(),
            include_subdomains in any::<bool>(),
            max_age in 0u64..=200_000_000u64,
        ) {
            let mut options = HstsOptions::new().max_age(max_age);
            if include_subdomains { options = options.include_subdomains(); }
            if preload { options = options.preload(); }

            let result = Shield::new().hsts(options);

            if max_age == 0 {
                // expect validation failure
                let err = match result {
                    Err(ShieldError::ExecutorValidationFailed(err)) => err,
                    Ok(_) => panic!("expected validation failure, but feature was accepted"),
                    Err(other) => panic!("expected validation failure, got different error: {other}"),
                };
                let err = err.downcast::<HstsOptionsError>().map(|b| *b).unwrap();
                prop_assert!(matches!(err, HstsOptionsError::InvalidMaxAge));
                return Ok(());
            }

            if preload && !include_subdomains {
                let err = match result {
                    Err(ShieldError::ExecutorValidationFailed(err)) => err,
                    Ok(_) => panic!("expected validation failure, but feature was accepted"),
                    Err(other) => panic!("expected validation failure, got different error: {other}"),
                };
                let err = err.downcast::<HstsOptionsError>().map(|b| *b).unwrap();
                prop_assert!(matches!(err, HstsOptionsError::PreloadRequiresIncludeSubdomains));
                return Ok(());
            }

            if preload && max_age < 31_536_000 {
                let err = match result {
                    Err(ShieldError::ExecutorValidationFailed(err)) => err,
                    Ok(_) => panic!("expected validation failure, but feature was accepted"),
                    Err(other) => panic!("expected validation failure, got different error: {other}"),
                };
                let err = err.downcast::<HstsOptionsError>().map(|b| *b).unwrap();
                prop_assert!(matches!(err, HstsOptionsError::PreloadRequiresLongMaxAge));
                return Ok(());
            }

            prop_assert!(result.is_ok());
        }
    }
}
