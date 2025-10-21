use bunner_shield_rs::{ReferrerPolicyOptions, ReferrerPolicyValue, Shield};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_referrer_policy(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Referrer-Policy".to_string(), value.to_string());
    headers
}

fn assert_policy(policy: ReferrerPolicyValue, expected: &str) {
    let shield = Shield::new()
        .referrer_policy(ReferrerPolicyOptions::new().policy(policy))
        .expect("feature");

    let result = shield.secure(empty_headers()).expect("secure");

    assert_eq!(
        result.get("Referrer-Policy").map(String::as_str),
        Some(expected)
    );
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_strict_origin_when_cross_origin() {
        let result = Shield::new()
            .referrer_policy(ReferrerPolicyOptions::new())
            .expect("feature")
            .secure(empty_headers())
            .expect("secure");

        assert_eq!(
            result.get("Referrer-Policy").map(String::as_str),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[test]
    fn given_no_referrer_policy_when_secure_then_sets_no_referrer_value() {
        assert_policy(ReferrerPolicyValue::NoReferrer, "no-referrer");
    }

    #[test]
    fn given_no_referrer_when_downgrade_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::NoReferrerWhenDowngrade,
            "no-referrer-when-downgrade",
        );
    }

    #[test]
    fn given_same_origin_policy_when_secure_then_sets_same_origin_value() {
        assert_policy(ReferrerPolicyValue::SameOrigin, "same-origin");
    }

    #[test]
    fn given_origin_policy_when_secure_then_sets_origin_value() {
        assert_policy(ReferrerPolicyValue::Origin, "origin");
    }

    #[test]
    fn given_strict_origin_policy_when_secure_then_sets_strict_origin_value() {
        assert_policy(ReferrerPolicyValue::StrictOrigin, "strict-origin");
    }

    #[test]
    fn given_origin_when_cross_origin_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::OriginWhenCrossOrigin,
            "origin-when-cross-origin",
        );
    }

    #[test]
    fn given_strict_origin_when_cross_origin_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin,
            "strict-origin-when-cross-origin",
        );
    }

    #[test]
    fn given_unsafe_url_policy_when_secure_then_sets_unsafe_url_value() {
        assert_policy(ReferrerPolicyValue::UnsafeUrl, "unsafe-url");
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_referrer_policy() {
        let shield = Shield::new()
            .referrer_policy(ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::SameOrigin))
            .expect("feature");

        let result = shield
            .secure(with_referrer_policy("unsafe-url"))
            .expect("secure");

        assert_eq!(
            result.get("Referrer-Policy").map(String::as_str),
            Some("same-origin")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_preserves_them() {
        let shield = Shield::new()
            .referrer_policy(ReferrerPolicyOptions::new())
            .expect("feature");

        let mut headers = with_referrer_policy("unsafe");
        headers.insert("Cache-Control".to_string(), "no-cache".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Cache-Control").map(String::as_str),
            Some("no-cache")
        );
    }
}

mod proptests {
    use super::*;

    // Strategy generating arbitrary non-target headers, avoiding the Referrer-Policy key
    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("Referrer-Policy") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn rp_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Referrer-Policy".len()).prop_map(|mask| {
            "Referrer-Policy"
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

    // Random policy strategy
    fn rp_value_strategy() -> impl Strategy<Value = ReferrerPolicyValue> {
        prop_oneof![
            Just(ReferrerPolicyValue::NoReferrer),
            Just(ReferrerPolicyValue::NoReferrerWhenDowngrade),
            Just(ReferrerPolicyValue::SameOrigin),
            Just(ReferrerPolicyValue::Origin),
            Just(ReferrerPolicyValue::StrictOrigin),
            Just(ReferrerPolicyValue::OriginWhenCrossOrigin),
            Just(ReferrerPolicyValue::StrictOriginWhenCrossOrigin),
            Just(ReferrerPolicyValue::UnsafeUrl),
        ]
    }

    fn rp_value_str(policy: ReferrerPolicyValue) -> &'static str {
        match policy {
            ReferrerPolicyValue::NoReferrer => "no-referrer",
            ReferrerPolicyValue::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicyValue::SameOrigin => "same-origin",
            ReferrerPolicyValue::Origin => "origin",
            ReferrerPolicyValue::StrictOrigin => "strict-origin",
            ReferrerPolicyValue::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicyValue::UnsafeUrl => "unsafe-url",
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_then_sets_policy_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((rp_case_strategy(), header_value_strategy())),
            policy in rp_value_strategy(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .referrer_policy(ReferrerPolicyOptions::new().policy(policy))
                .expect("feature");

            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_,_>>();
            expected.insert("Referrer-Policy".to_string(), rp_value_str(policy).to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_rp_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (rp_case_strategy(), rp_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_rp_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
            policy in rp_value_strategy(),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new()
                .referrer_policy(ReferrerPolicyOptions::new().policy(policy))
                .expect("feature");

            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_,_>>();
            expected.insert("Referrer-Policy".to_string(), rp_value_str(policy).to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
