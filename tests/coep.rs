use bunner_shield_rs::{CoepOptions, CoepPolicy, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_require_corp() {
    let shield = Shield::new().coep(CoepOptions::new()).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "coep"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Embedder-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
            .map(String::as_str),
        Some("require-corp"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "coep"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Embedder-Policy header")
    }));
}

#[test]
fn given_credentialless_policy_when_secure_then_sets_header() {
    let options = CoepOptions::new().policy(CoepPolicy::Credentialless);
    let shield = Shield::new().coep(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "coep"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Embedder-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
            .map(String::as_str),
        Some("credentialless"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "coep"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Embedder-Policy header")
    }));
}
