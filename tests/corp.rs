use bunner_shield_rs::{CorpOptions, CorpPolicy, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_same_origin() {
    let shield = Shield::new().corp(CorpOptions::new()).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Resource-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("same-origin"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Resource-Policy header")
    }));
}

#[test]
fn given_same_site_policy_when_secure_then_sets_header() {
    let options = CorpOptions::new().policy(CorpPolicy::SameSite);
    let shield = Shield::new().corp(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Resource-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("same-site"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Resource-Policy header")
    }));
}

#[test]
fn given_cross_origin_policy_when_secure_then_sets_header() {
    let options = CorpOptions::new().policy(CorpPolicy::CrossOrigin);
    let shield = Shield::new().corp(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Resource-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
            .map(String::as_str),
        Some("cross-origin"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "corp"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Resource-Policy header")
    }));
}
