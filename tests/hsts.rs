use bunner_shield_rs::{HstsOptions, Shield, ShieldError, header_keys};
use std::collections::HashMap;

#[test]
fn given_valid_hsts_when_secure_then_applies_header() {
    let options = HstsOptions::new().include_subdomains();
    let shield = Shield::new().hsts(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "hsts"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured HSTS policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::STRICT_TRANSPORT_SECURITY)
            .map(String::as_str),
        Some("max-age=31536000; includeSubDomains")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "hsts"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Strict-Transport-Security header")
    }));
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
