use bunner_shield_rs::{HstsOptions, Shield, ShieldError, header_keys};
use std::collections::HashMap;

#[test]
fn given_valid_hsts_when_secure_then_applies_header() {
    let options = HstsOptions::new().include_subdomains();
    let shield = Shield::new().hsts(options).expect("feature");
    let headers = HashMap::new();
    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::STRICT_TRANSPORT_SECURITY)
            .map(String::as_str),
        Some("max-age=31536000; includeSubDomains")
    );
}

#[test]
fn given_invalid_preload_combo_when_add_feature_then_returns_error() {
    let options = HstsOptions::new().preload();
    let result = Shield::new().hsts(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
