use bunner_shield_rs::{CoepOptions, CoepOptionsError, CoepPolicy, Shield};
use std::collections::HashMap;
mod common;
use common::empty_headers;

fn with_coep(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        "Cross-Origin-Embedder-Policy".to_string(),
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
