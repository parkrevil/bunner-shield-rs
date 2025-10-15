use bunner_shield_rs::{Shield, header_keys, header_values};
use std::collections::HashMap;

#[test]
fn given_headers_without_x_download_options_when_secure_then_sets_header() {
    let shield = Shield::new()
        .x_download_options()
        .expect("x-download-options feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-download-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Download-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_DOWNLOAD_OPTIONS)
            .map(String::as_str),
        Some(header_values::X_DOWNLOAD_OPTIONS_NOOPEN)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-download-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted X-Download-Options header")
    }));
}

#[test]
fn given_existing_x_download_options_when_secure_then_overwrites_with_noopen() {
    let shield = Shield::new()
        .x_download_options()
        .expect("x-download-options feature");
    let mut headers = HashMap::new();
    headers.insert("X-Download-Options".to_string(), "invalid".to_string());

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-download-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Download-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_DOWNLOAD_OPTIONS)
            .map(String::as_str),
        Some(header_values::X_DOWNLOAD_OPTIONS_NOOPEN)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-download-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted X-Download-Options header")
    }));
}
