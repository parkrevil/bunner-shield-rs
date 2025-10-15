use bunner_shield_rs::{CoopOptions, CoopPolicy, Shield, header_keys, header_values};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_coop(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::CROSS_ORIGIN_OPENER_POLICY.to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_same_origin_policy() {
        let shield = Shield::new().coop(CoopOptions::new()).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN)
        );
    }

    #[test]
    fn given_same_origin_allow_popups_when_secure_then_sets_allow_popups_value() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN_ALLOW_POPUPS)
        );
    }

    #[test]
    fn given_unsafe_none_policy_when_secure_then_sets_unsafe_none_value() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::UnsafeNone))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_UNSAFE_NONE)
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_opener_policy() {
        let shield = Shield::new().coop(CoopOptions::new()).expect("feature");

        let result = shield.secure(with_coop("legacy")).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN)
        );
    }

    #[test]
    fn given_unrelated_headers_when_secure_then_keeps_them_intact() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::SameOrigin))
            .expect("feature");

        let mut headers = with_coop("legacy");
        headers.insert("X-Trace".to_string(), "abc".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Trace").map(String::as_str), Some("abc"));
        assert_eq!(
            result
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN)
        );
    }
}
