use bunner_shield_rs::{CorpOptions, CorpPolicy, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_same_origin() {
    let shield = Shield::new().corp(CorpOptions::new()).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("same-origin"),
    );
}

#[test]
fn given_same_site_policy_when_secure_then_sets_header() {
    let options = CorpOptions::new().policy(CorpPolicy::SameSite);
    let shield = Shield::new().corp(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("same-site"),
    );
}

#[test]
fn given_cross_origin_policy_when_secure_then_sets_header() {
    let options = CorpOptions::new().policy(CorpPolicy::CrossOrigin);
    let shield = Shield::new().corp(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("cross-origin"),
    );
}
