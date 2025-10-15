use bunner_shield_rs::{Shield, header_keys, header_values};
use std::collections::HashMap;

#[test]
fn given_headers_without_nosniff_when_secure_then_sets_header() {
    let shield = Shield::new().x_content_type_options().expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-content-type-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Content-Type-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_CONTENT_TYPE_OPTIONS)
            .map(String::as_str),
        Some(header_values::NOSNIFF)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-content-type-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-Content-Type-Options header")
    }));
}

#[test]
fn given_existing_header_when_secure_then_overwrites_with_nosniff() {
    let shield = Shield::new().x_content_type_options().expect("feature");
    let mut headers = HashMap::new();
    headers.insert("X-Content-Type-Options".to_string(), "whatever".to_string());

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-content-type-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Content-Type-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_CONTENT_TYPE_OPTIONS)
            .map(String::as_str),
        Some(header_values::NOSNIFF)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-content-type-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-Content-Type-Options header")
    }));
}
