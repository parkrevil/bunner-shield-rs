use bunner_shield_rs::{OriginAgentClusterOptions, Shield};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_oac(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Origin-Agent-Cluster".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_enable_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?1")
        );
    }

    #[test]
    fn given_disabled_options_when_secure_then_sets_disable_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?0")
        );
    }

    #[test]
    fn given_disable_then_enable_when_secure_then_respects_last_override() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable().enable())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?1")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("feature");

        let result = shield.secure(with_oac("?1")).expect("secure");

        assert_eq!(
            result.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?0")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_unchanged() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new())
            .expect("feature");

        let mut headers = with_oac("?0");
        headers.insert("X-Env".to_string(), "prod".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Env").map(String::as_str), Some("prod"));
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
                    if key.eq_ignore_ascii_case("Origin-Agent-Cluster") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn header_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Origin-Agent-Cluster".len()).prop_map(|mask| {
            "Origin-Agent-Cluster"
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
        fn given_any_headers_and_optional_existing_when_secure_with_enable_then_sets_marker_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .origin_agent_cluster(OriginAgentClusterOptions::new().enable())
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("Origin-Agent-Cluster".to_string(), "?1".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_with_disable_then_sets_marker_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((header_case_strategy(), header_value_strategy())),
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline { headers.insert(name.clone(), value.clone()); }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("Origin-Agent-Cluster".to_string(), "?0".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
