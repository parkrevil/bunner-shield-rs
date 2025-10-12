use bunner_shield_rs::{CoepOptions, CoepPolicy, Shield, ShieldError, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_require_corp() {
    let shield = Shield::new().coep(CoepOptions::new()).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
            .map(String::as_str),
        Some("require-corp"),
    );
}

#[test]
fn given_credentialless_policy_when_secure_then_sets_header() {
    let options = CoepOptions::new().policy(CoepPolicy::Credentialless);
    let shield = Shield::new().coep(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
            .map(String::as_str),
        Some("credentialless"),
    );
}

#[test]
fn given_missing_cache_warning_when_add_feature_then_returns_error() {
    let options = CoepOptions::new()
        .policy(CoepPolicy::Credentialless)
        .cache_warning(false);
    let result = Shield::new().coep(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
