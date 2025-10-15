use bunner_shield_rs::{
    ReferrerPolicyOptions, ReferrerPolicyValue, Shield, header_keys, header_values,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_referrer_policy(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(header_keys::REFERRER_POLICY.to_string(), value.to_string());
    headers
}

fn assert_policy(policy: ReferrerPolicyValue, expected: &str) {
    let shield = Shield::new()
        .referrer_policy(ReferrerPolicyOptions::new().policy(policy))
        .expect("feature");

    let result = shield.secure(empty_headers()).expect("secure");

    assert_eq!(
        result.get(header_keys::REFERRER_POLICY).map(String::as_str),
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
            result.get(header_keys::REFERRER_POLICY).map(String::as_str),
            Some(header_values::REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
        );
    }

    #[test]
    fn given_no_referrer_policy_when_secure_then_sets_no_referrer_value() {
        assert_policy(
            ReferrerPolicyValue::NoReferrer,
            header_values::REFERRER_POLICY_NO_REFERRER,
        );
    }

    #[test]
    fn given_no_referrer_when_downgrade_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::NoReferrerWhenDowngrade,
            header_values::REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE,
        );
    }

    #[test]
    fn given_same_origin_policy_when_secure_then_sets_same_origin_value() {
        assert_policy(
            ReferrerPolicyValue::SameOrigin,
            header_values::REFERRER_POLICY_SAME_ORIGIN,
        );
    }

    #[test]
    fn given_origin_policy_when_secure_then_sets_origin_value() {
        assert_policy(
            ReferrerPolicyValue::Origin,
            header_values::REFERRER_POLICY_ORIGIN,
        );
    }

    #[test]
    fn given_strict_origin_policy_when_secure_then_sets_strict_origin_value() {
        assert_policy(
            ReferrerPolicyValue::StrictOrigin,
            header_values::REFERRER_POLICY_STRICT_ORIGIN,
        );
    }

    #[test]
    fn given_origin_when_cross_origin_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::OriginWhenCrossOrigin,
            header_values::REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN,
        );
    }

    #[test]
    fn given_strict_origin_when_cross_origin_policy_when_secure_then_sets_expected_value() {
        assert_policy(
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin,
            header_values::REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
        );
    }

    #[test]
    fn given_unsafe_url_policy_when_secure_then_sets_unsafe_url_value() {
        assert_policy(
            ReferrerPolicyValue::UnsafeUrl,
            header_values::REFERRER_POLICY_UNSAFE_URL,
        );
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
            .secure(with_referrer_policy(
                header_values::REFERRER_POLICY_UNSAFE_URL,
            ))
            .expect("secure");

        assert_eq!(
            result.get(header_keys::REFERRER_POLICY).map(String::as_str),
            Some(header_values::REFERRER_POLICY_SAME_ORIGIN)
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
