use bunner_shield_rs::{
    CorpOptions, CorpOptionsError, CorpPolicy, Shield, header_keys, header_values,
};
use std::collections::HashMap;
mod common;
use common::empty_headers;

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
