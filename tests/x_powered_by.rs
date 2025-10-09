use bunner_shield_rs::{Shield, headers};
use std::collections::HashMap;

#[test]
fn given_standard_header_when_secure_then_removes_x_powered_by() {
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".to_string(), "Express".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let shield = Shield::new().x_powered_by().expect("feature");
    let result = shield.secure(headers).expect("secure");

    assert!(!result.contains_key(headers::X_POWERED_BY));
    assert_eq!(
        result.get("Content-Type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn given_mixed_case_header_when_secure_then_removes_x_powered_by() {
    let mut headers = HashMap::new();
    headers.insert("x-PoWeReD-bY".to_string(), "Express".to_string());
    let shield = Shield::new().x_powered_by().expect("feature");
    let result = shield.secure(headers).expect("secure");

    assert!(!result.contains_key(headers::X_POWERED_BY));
}
