use bunner_shield_rs::{
    CorpOptions, CorpOptionsError, CorpPolicy, Shield, header_keys, header_values,
};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_corp(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::CROSS_ORIGIN_RESOURCE_POLICY.to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_same_origin_policy() {
        let shield = Shield::new().corp(CorpOptions::new()).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_ORIGIN)
        );
    }

    #[test]
    fn given_same_site_policy_when_secure_then_sets_same_site_value() {
        let shield = Shield::new()
            .corp(CorpOptions::new().policy(CorpPolicy::SameSite))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_SITE)
        );
    }

    #[test]
    fn given_cross_origin_policy_when_secure_then_sets_cross_origin_value() {
        let shield = Shield::new()
            .corp(CorpOptions::new().policy(CorpPolicy::CrossOrigin))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_CROSS_ORIGIN)
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_resource_policy() {
        let shield = Shield::new().corp(CorpOptions::new()).expect("feature");

        let result = shield.secure(with_corp("legacy")).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_ORIGIN)
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_preserves_them() {
        let shield = Shield::new().corp(CorpOptions::new()).expect("feature");

        let mut headers = with_corp("legacy");
        headers.insert("X-Request-Id".to_string(), "42".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Request-Id").map(String::as_str), Some("42"));
        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_ORIGIN)
        );
    }
}

mod failure {
    use super::*;

    #[test]
    fn given_unknown_policy_when_building_options_then_returns_invalid_policy_error() {
        let error = CorpOptions::from_policy_str("forbidden").unwrap_err();

        assert!(matches!(
            error,
            CorpOptionsError::InvalidPolicy(value) if value == "forbidden"
        ));
    }

    #[test]
    fn given_whitespace_policy_when_building_options_then_normalizes_before_match() {
        let options = CorpOptions::from_policy_str("  same-site  ").expect("policy");
        let shield = Shield::new().corp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_SITE)
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
                    if key.eq_ignore_ascii_case(header_keys::CROSS_ORIGIN_RESOURCE_POLICY) {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy() -> impl Strategy<Value = String> {
        let canonical = header_keys::CROSS_ORIGIN_RESOURCE_POLICY;
        prop::collection::vec(prop::bool::ANY, canonical.len()).prop_map(move |mask| {
            canonical
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

    fn expected_value_for(policy: CorpPolicy) -> &'static str {
        match policy {
            CorpPolicy::SameOrigin => header_values::CORP_SAME_ORIGIN,
            CorpPolicy::SameSite => header_values::CORP_SAME_SITE,
            CorpPolicy::CrossOrigin => header_values::CORP_CROSS_ORIGIN,
        }
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
            policy in prop_oneof![
                Just(CorpPolicy::SameOrigin),
                Just(CorpPolicy::SameSite),
                Just(CorpPolicy::CrossOrigin)
            ],
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let options = CorpOptions::new().policy(policy.clone());
            let expected_value = expected_value_for(policy);

            let shield = Shield::new().corp(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert(header_keys::CROSS_ORIGIN_RESOURCE_POLICY.to_string(), expected_value.to_string());

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
            policy in prop_oneof![
                Just(CorpPolicy::SameOrigin),
                Just(CorpPolicy::SameSite),
                Just(CorpPolicy::CrossOrigin)
            ],
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            // insert two differently-cased CORP entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let options = CorpOptions::new().policy(policy.clone());
            let expected_value = expected_value_for(policy);

            let shield = Shield::new().corp(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert(header_keys::CROSS_ORIGIN_RESOURCE_POLICY.to_string(), expected_value.to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
