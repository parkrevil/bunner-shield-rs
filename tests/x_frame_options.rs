use bunner_shield_rs::{Shield, XFrameOptionsOptions, XFrameOptionsPolicy, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_deny() {
    let options = XFrameOptionsOptions::new();
    let shield = Shield::new().x_frame_options(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-frame-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured X-Frame-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
        Some("DENY")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-frame-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted X-Frame-Options header")
    }));
}

#[test]
fn given_same_origin_policy_when_secure_then_sets_sameorigin() {
    let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);
    let shield = Shield::new().x_frame_options(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-frame-options"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured X-Frame-Options policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
        Some("SAMEORIGIN")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-frame-options"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted X-Frame-Options header")
    }));
}
