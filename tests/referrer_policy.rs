use bunner_shield_rs::{ReferrerPolicyOptions, ReferrerPolicyValue, Shield};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

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
