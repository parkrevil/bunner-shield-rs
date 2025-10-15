use bunner_shield_rs::{NelOptions, ReportKind, ReportSeverity, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_nel_options_with_report_to_when_secure_then_sets_header_and_reports() {
    let options = NelOptions::new()
        .report_to("default")
        .max_age(86_400)
        .include_subdomains(true)
        .failure_fraction(0.25)
        .success_fraction(0.5)
        .reporting_endpoint("default", "https://reports.example.com");
    let shield = Shield::new().nel(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Validation
            && entry.message.contains("Configured NEL policy")
    }));
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Validation
            && entry
                .message
                .contains("Configured reporting endpoints: default -> https://reports.example.com")
    }));

    let result = shield.secure(headers).expect("secure");

    assert!(result.contains_key(header_keys::NEL));
    let report_to_header = result
        .get(header_keys::REPORT_TO)
        .expect("report-to header");
    assert!(report_to_header.contains("\"group\":\"default\""));
    assert!(report_to_header.contains("https://reports.example.com"));

    assert_eq!(
        result
            .get(header_keys::REPORTING_ENDPOINTS)
            .map(String::as_str),
        Some("default=\"https://reports.example.com\"")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.message.contains("Emitted NEL header")
    }));
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.message.contains("Added Report-To entry")
    }));
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "nel"
            && entry.kind == ReportKind::Runtime
            && entry.message.contains("Added Reporting-Endpoints entry")
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
