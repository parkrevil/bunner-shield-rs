use bunner_shield_rs::{NelOptions, ReportKind, ReportSeverity, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_nel_options_with_report_to_when_secure_then_sets_header_and_reports() {
    let options = NelOptions::new()
        .report_to("default")
        .max_age(86_400)
        .include_subdomains(true)
        .failure_fraction(0.25)
        .success_fraction(0.5);
    let shield = Shield::new().nel(options).expect("feature");
    let mut headers = HashMap::new();
    headers.insert(header_keys::REPORT_TO.to_string(), "{}".to_string());

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Validation
            && entry.message.contains("Configured NEL policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert!(result.contains_key(header_keys::NEL));

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.message.contains("Emitted NEL header")
    }));
    assert!(!runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.severity == ReportSeverity::Warning
    }));
}

#[test]
fn given_nel_without_report_to_when_secure_then_emits_warning() {
    let shield = Shield::new().nel(NelOptions::new()).expect("feature");
    let headers = HashMap::new();

    let _ = shield.take_report_entries();

    let result = shield.secure(headers).expect("secure");
    assert!(result.contains_key(header_keys::NEL));

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.severity == ReportSeverity::Warning
            && entry
                .message
                .contains("NEL header emitted without matching Report-To header")
    }));
}
