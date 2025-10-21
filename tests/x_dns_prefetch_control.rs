use bunner_shield_rs::{Shield, XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_prefetch(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("X-DNS-Prefetch-Control".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_off_policy() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("X-DNS-Prefetch-Control").map(String::as_str),
            Some("off")
        );
    }

    #[test]
    fn given_on_policy_when_secure_then_sets_on_value() {
        let shield = Shield::new()
            .x_dns_prefetch_control(
                XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
            )
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("X-DNS-Prefetch-Control").map(String::as_str),
            Some("on")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_configured_value() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let result = shield.secure(with_prefetch("on")).expect("secure");

        assert_eq!(
            result.get("X-DNS-Prefetch-Control").map(String::as_str),
            Some("off")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_keeps_them() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let mut headers = with_prefetch("on");
        headers.insert("X-Cache".to_string(), "HIT".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Cache").map(String::as_str), Some("HIT"));
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
                    if key.eq_ignore_ascii_case("X-DNS-Prefetch-Control") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "X-DNS-Prefetch-Control".len()).prop_map(|mask| {
            "X-DNS-Prefetch-Control"
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

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_off_then_sets_constant_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("X-DNS-Prefetch-Control".to_string(), "off".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_on_then_sets_constant_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .x_dns_prefetch_control(XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On))
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("X-DNS-Prefetch-Control".to_string(), "on".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
