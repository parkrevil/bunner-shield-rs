use bunner_shield_rs::{ReferrerPolicyOptions, ReferrerPolicyValue, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_strict_origin_when_cross_origin() {
    let options = ReferrerPolicyOptions::new();
    let shield = Shield::new().referrer_policy(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "referrer-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured Referrer-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::REFERRER_POLICY).map(String::as_str),
        Some("strict-origin-when-cross-origin"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "referrer-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted Referrer-Policy header")
    }));
}

#[test]
fn given_custom_policy_when_secure_then_sets_requested_value() {
    let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::NoReferrer);
    let shield = Shield::new().referrer_policy(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "referrer-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured Referrer-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::REFERRER_POLICY).map(String::as_str),
        Some("no-referrer"),
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "referrer-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted Referrer-Policy header")
    }));
}
