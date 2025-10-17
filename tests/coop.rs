use bunner_shield_rs::{CoopOptions, CoopOptionsError, CoopPolicy, Shield};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_coop(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Cross-Origin-Opener-Policy".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_same_origin_policy() {
        let shield = Shield::new().coop(CoopOptions::new()).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin")
        );
    }

    #[test]
    fn given_same_origin_allow_popups_when_secure_then_sets_allow_popups_value() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin-allow-popups")
        );
    }

    #[test]
    fn given_unsafe_none_policy_when_secure_then_sets_unsafe_none_value() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::UnsafeNone))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("unsafe-none")
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
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin")
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
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin")
        );
    }
}

mod failure {
    use super::*;

    #[test]
    fn given_unknown_policy_when_building_options_then_returns_invalid_policy_error() {
        let error = CoopOptions::from_policy_str("disallowed").unwrap_err();

        assert!(matches!(
            error,
            CoopOptionsError::InvalidPolicy(value) if value == "disallowed"
        ));
    }

    #[test]
    fn given_uppercase_policy_when_building_options_then_matches_known_variant() {
        let options = CoopOptions::from_policy_str("SAME-ORIGIN-ALLOW-POPUPS").expect("policy");
        let shield = Shield::new().coop(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin-allow-popups")
        );
    }

    #[test]
    fn given_policy_with_padding_when_building_options_then_trims_before_matching() {
        let options = CoopOptions::from_policy_str("  unsafe-none  ").expect("policy");
        let shield = Shield::new().coop(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("unsafe-none")
        );
    }
}
