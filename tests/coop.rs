use bunner_shield_rs::{CoopOptions, CoopPolicy, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_same_origin() {
    let shield = Shield::new().coop(CoopOptions::new()).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("same-origin"),
    );
}

#[test]
fn given_allow_popups_policy_when_secure_then_sets_header() {
    let options = CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups);
    let shield = Shield::new().coop(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("same-origin-allow-popups"),
    );
}

#[test]
fn given_unsafe_none_policy_when_secure_then_sets_header() {
    let options = CoopOptions::new().policy(CoopPolicy::UnsafeNone);
    let shield = Shield::new().coop(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("unsafe-none"),
    );
}
