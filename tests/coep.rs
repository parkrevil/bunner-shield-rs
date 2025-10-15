use bunner_shield_rs::{CoepOptions, CoepPolicy, Shield, header_keys, header_values};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_coep(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::CROSS_ORIGIN_EMBEDDER_POLICY.to_string(),
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
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_REQUIRE_CORP)
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
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_CREDENTIALLESS)
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
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_REQUIRE_CORP)
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
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_REQUIRE_CORP)
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
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_REQUIRE_CORP)
        );
    }
}
