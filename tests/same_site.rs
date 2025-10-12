use bunner_shield_rs::{header_keys, SameSiteOptions, SameSitePolicy, Shield, ShieldError};
use std::collections::HashMap;

#[test]
fn given_cookie_without_attributes_when_secure_then_sets_defaults() {
    let options = SameSiteOptions::new();
    let shield = Shield::new().same_site(options).expect("feature");
    let mut headers = HashMap::new();
    headers.insert(
        header_keys::SET_COOKIE.to_string(),
        "session=abc".to_string(),
    );

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::SET_COOKIE).map(String::as_str),
        Some("session=abc; Secure; HttpOnly; SameSite=Lax")
    );
}

#[test]
fn given_cookie_with_attributes_when_secure_then_overwrites_policy() {
    let options = SameSiteOptions::new().http_only(false).same_site(SameSitePolicy::Strict);
    let shield = Shield::new().same_site(options).expect("feature");
    let mut headers = HashMap::new();
    headers.insert(
        header_keys::SET_COOKIE.to_string(),
        "session=abc; SameSite=None; Secure".to_string(),
    );

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::SET_COOKIE).map(String::as_str),
        Some("session=abc; Secure; SameSite=Strict")
    );
}

#[test]
fn given_none_without_secure_when_add_feature_then_returns_error() {
    let options = SameSiteOptions::new().secure(false).same_site(SameSitePolicy::None);
    let result = Shield::new().same_site(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
