use bunner_shield_rs::{Shield, XFrameOptionsOptions, XFrameOptionsPolicy};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_xfo(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("X-Frame-Options".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_deny() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("X-Frame-Options").map(String::as_str),
            Some("DENY")
        );
    }

    #[test]
    fn given_same_origin_policy_when_secure_then_sets_sameorigin() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_configured_policy() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let result = shield.secure(with_xfo("ALLOW")).expect("secure");

        assert_eq!(
            result.get("X-Frame-Options").map(String::as_str),
            Some("DENY")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_intact() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let mut headers = with_xfo("ALLOW");
        headers.insert("X-Trace".to_string(), "abc".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Trace").map(String::as_str), Some("abc"));
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
                    if key.eq_ignore_ascii_case("X-Frame-Options") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn xfo_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "X-Frame-Options".len()).prop_map(|mask| {
            "X-Frame-Options"
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
        fn given_any_headers_and_optional_existing_when_secure_with_deny_then_sets_constant_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((xfo_case_strategy(), header_value_strategy())),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .x_frame_options(XFrameOptionsOptions::new())
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");
            // Build expected from the deduplicated baseline
            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("X-Frame-Options".to_string(), "DENY".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_sameorigin_then_sets_constant_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((xfo_case_strategy(), header_value_strategy())),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");
            // Build expected from the deduplicated baseline
            let mut expected: HashMap<String, String> = baseline.into_iter().collect();
            expected.insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_xfo_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (xfo_case_strategy(), xfo_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_with_deny_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_xfo_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            // Insert two differently-cased XFO entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new()
                .x_frame_options(XFrameOptionsOptions::new())
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("X-Frame-Options".to_string(), "DENY".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_with_sameorigin_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_xfo_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            // Insert two differently-cased XFO entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new()
                .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
