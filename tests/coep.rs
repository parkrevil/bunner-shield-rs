use bunner_shield_rs::{CoepOptions, CoepOptionsError, CoepPolicy, Shield};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_coep(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        "Cross-Origin-Embedder-Policy".to_string(),
        value.to_string(),
    );
    headers
}

fn with_coep_report_only(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        "Cross-Origin-Embedder-Policy-Report-Only".to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_applies_require_corp_policy() {
        let shield = Shield::new().coep(CoepOptions::new()).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    #[test]
    fn given_credentialless_policy_when_secure_then_sets_credentialless_value() {
        let shield = Shield::new()
            .coep(CoepOptions::new().policy(CoepPolicy::Credentialless))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("credentialless")
        );
    }

    #[test]
    fn given_require_corp_policy_when_secure_then_sets_require_corp_value() {
        let shield = Shield::new()
            .coep(CoepOptions::new().policy(CoepPolicy::RequireCorp))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    #[test]
    fn given_report_only_options_when_secure_then_sets_report_only_header() {
        let shield = Shield::new()
            .coep(CoepOptions::new().report_only())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy-Report-Only")
                .map(String::as_str),
            Some("require-corp")
        );
        assert!(!result.contains_key("Cross-Origin-Embedder-Policy"));
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_embedder_policy() {
        let shield = Shield::new().coep(CoepOptions::new()).expect("feature");

        let result = shield.secure(with_coep("unsafe-value")).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    #[test]
    fn given_existing_report_only_header_when_secure_then_overwrites_report_only_value() {
        let shield = Shield::new()
            .coep(CoepOptions::new().report_only())
            .expect("feature");

        let result = shield
            .secure(with_coep_report_only("unsafe-value"))
            .expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy-Report-Only")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    #[test]
    fn given_unrelated_headers_when_secure_then_preserves_them() {
        let shield = Shield::new().coep(CoepOptions::new()).expect("feature");

        let mut headers = with_coep("unsafe-value");
        headers.insert("Cache-Control".to_string(), "no-store".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }
}

mod failure {
    use super::*;

    #[test]
    fn given_unknown_policy_when_building_options_then_returns_invalid_policy_error() {
        let error = CoepOptions::from_policy_str("invalid-policy").unwrap_err();

        assert!(matches!(
            error,
            CoepOptionsError::InvalidPolicy(value) if value == "invalid-policy"
        ));
    }

    #[test]
    fn given_mixed_case_when_building_options_then_normalizes_to_known_policy() {
        let options = CoepOptions::from_policy_str("ReQuIrE-CoRp").expect("policy");
        let shield = Shield::new().coep(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
    }

    #[test]
    fn given_policy_with_whitespace_when_building_options_then_trims_before_matching() {
        let options = CoepOptions::from_policy_str("  credentialless  ").expect("policy");
        let shield = Shield::new().coep(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("credentialless")
        );
    }
}

mod proptests {
    use super::*;

    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("Cross-Origin-Embedder-Policy") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Cross-Origin-Embedder-Policy".len()).prop_map(
            |mask| {
                "Cross-Origin-Embedder-Policy"
                    .chars()
                    .zip(mask)
                    .map(|(ch, lower)| match ch {
                        '-' => '-',
                        letter if lower => letter.to_ascii_lowercase(),
                        letter => letter.to_ascii_uppercase(),
                    })
                    .collect()
            },
        )
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
        fn given_any_headers_and_optional_existing_when_secure_then_sets_policy_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
            // choose policy variant
            use_credentialless in any::<bool>(),
            use_report_only in any::<bool>(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let mut options = if use_credentialless {
                CoepOptions::new().policy(CoepPolicy::Credentialless)
            } else {
                CoepOptions::new().policy(CoepPolicy::RequireCorp)
            };
            if use_report_only {
                options = options.report_only();
            }
            let expected_value = if use_credentialless { "credentialless" } else { "require-corp" };
            let expected_key = if use_report_only {
                "Cross-Origin-Embedder-Policy-Report-Only"
            } else {
                "Cross-Origin-Embedder-Policy"
            };

            let shield = Shield::new().coep(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            if use_report_only {
                expected.retain(|key, _| !key.eq_ignore_ascii_case("Cross-Origin-Embedder-Policy"));
            }
            expected.insert(expected_key.to_string(), expected_value.to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_header_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (header_case_strategy(), header_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_header_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
            use_credentialless in any::<bool>(),
            use_report_only in any::<bool>(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            // insert two differently-cased COEP entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let mut options = if use_credentialless {
                CoepOptions::new().policy(CoepPolicy::Credentialless)
            } else {
                CoepOptions::new().policy(CoepPolicy::RequireCorp)
            };
            if use_report_only {
                options = options.report_only();
            }
            let expected_value = if use_credentialless { "credentialless" } else { "require-corp" };
            let expected_key = if use_report_only {
                "Cross-Origin-Embedder-Policy-Report-Only"
            } else {
                "Cross-Origin-Embedder-Policy"
            };

            let shield = Shield::new().coep(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            if use_report_only {
                expected.retain(|key, _| !key.eq_ignore_ascii_case("Cross-Origin-Embedder-Policy"));
            }
            expected.insert(expected_key.to_string(), expected_value.to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
