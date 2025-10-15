use bunner_shield_rs::{CoopOptions, CoopPolicy, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_same_origin() {
    let shield = Shield::new().coop(CoopOptions::new()).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Opener-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("same-origin"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Opener-Policy header")
    }));
}

#[test]
fn given_allow_popups_policy_when_secure_then_sets_header() {
    let options = CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups);
    let shield = Shield::new().coop(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Opener-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("same-origin-allow-popups"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Opener-Policy header")
    }));
}

#[test]
fn given_unsafe_none_policy_when_secure_then_sets_header() {
    let options = CoopOptions::new().policy(CoopPolicy::UnsafeNone);
    let shield = Shield::new().coop(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Cross-Origin-Opener-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
            .map(String::as_str),
        Some("unsafe-none"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "coop"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Cross-Origin-Opener-Policy header")
    }));
}
