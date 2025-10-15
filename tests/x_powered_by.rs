use bunner_shield_rs::{Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_standard_header_when_secure_then_removes_x_powered_by() {
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".to_string(), "Express".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let shield = Shield::new().x_powered_by().expect("feature");

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-powered-by"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured to remove X-Powered-By header")
    }));

    let result = shield.secure(headers).expect("secure");

    assert!(!result.contains_key(header_keys::X_POWERED_BY));
    assert_eq!(
        result.get("Content-Type").map(String::as_str),
        Some("application/json")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-powered-by"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Removed X-Powered-By header")
    }));
}

#[test]
fn given_mixed_case_header_when_secure_then_removes_x_powered_by() {
    let mut headers = HashMap::new();
    headers.insert("x-PoWeReD-bY".to_string(), "Express".to_string());
    let shield = Shield::new().x_powered_by().expect("feature");

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-powered-by"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured to remove X-Powered-By header")
    }));

    let result = shield.secure(headers).expect("secure");

    assert!(!result.contains_key(header_keys::X_POWERED_BY));

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-powered-by"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Removed X-Powered-By header")
    }));
}
