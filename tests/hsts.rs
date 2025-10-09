use bunner_shield_rs::{HstsOptions, Shield, ShieldError, headers};
use std::collections::HashMap;

#[test]
fn given_valid_hsts_when_secure_then_applies_header() {
    let options = HstsOptions::new().include_subdomains();
    let shield = Shield::new()
        .strict_transport_security(options)
        .expect("feature");
    let headers = HashMap::new();
    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(headers::STRICT_TRANSPORT_SECURITY)
            .map(String::as_str),
        Some("max-age=31536000; includeSubDomains")
    );
}

#[test]
fn given_invalid_preload_combo_when_add_feature_then_returns_error() {
    let options = HstsOptions::new().enable_preload();
    let result = Shield::new().strict_transport_security(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
