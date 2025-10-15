use bunner_shield_rs::{PermissionsPolicyOptions, Shield, ShieldError, header_keys};
use std::collections::HashMap;

#[test]
fn given_policy_when_secure_then_sets_permissions_policy_header() {
    let options = PermissionsPolicyOptions::new("geolocation=()");
    let shield = Shield::new().permissions_policy(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::PERMISSIONS_POLICY)
            .map(String::as_str),
        Some("geolocation=()")
    );
}

#[test]
fn given_empty_policy_when_add_feature_then_returns_error() {
    let options = PermissionsPolicyOptions::new("");

    let result = Shield::new().permissions_policy(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
