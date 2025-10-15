use bunner_shield_rs::{CsrfOptions, Shield, ShieldError, header_keys};
use std::collections::HashMap;

#[test]
fn given_csrf_feature_when_secure_then_sets_cookie_and_header() {
    let options = CsrfOptions::new([11u8; 32]);
    let shield = Shield::new().csrf(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert!(result.contains_key(header_keys::CSRF_TOKEN));
    assert!(
        result
            .get(header_keys::SET_COOKIE)
            .expect("cookie")
            .contains("__Host-")
    );
}

#[test]
fn given_invalid_cookie_prefix_when_add_feature_then_returns_error() {
    let options = CsrfOptions::new([9u8; 32]).cookie_name("csrf");
    let result = Shield::new().csrf(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
