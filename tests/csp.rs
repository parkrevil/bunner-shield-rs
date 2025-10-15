use bunner_shield_rs::{CspOptions, CspSource, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_enforced_policy_when_secure_then_applies_csp_header() {
    let policy = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .base_uri([CspSource::None])
        .frame_ancestors([CspSource::None]);
    let shield = Shield::new().csp(policy).expect("feature");
    let mut headers = HashMap::new();
    headers.insert("X-Request-Id".to_string(), "abc-123".to_string());

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CONTENT_SECURITY_POLICY)
            .map(String::as_str),
        Some("default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
    );
    assert_eq!(
        result.get("X-Request-Id").map(String::as_str),
        Some("abc-123")
    );
}
