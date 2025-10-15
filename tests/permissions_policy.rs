use bunner_shield_rs::{
    CspReportGroup, PermissionsPolicyOptions, Shield, ShieldError, header_keys,
};
use std::collections::HashMap;

#[test]
fn given_policy_when_secure_then_sets_permissions_policy_header() {
    let options = PermissionsPolicyOptions::new("geolocation=()");
    let shield = Shield::new().permissions_policy(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry.message.contains("Configured Permissions-Policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::PERMISSIONS_POLICY)
            .map(String::as_str),
        Some("geolocation=()")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Emitted Permissions-Policy header")
    }));
}

#[test]
fn given_empty_policy_when_add_feature_then_returns_error() {
    let options = PermissionsPolicyOptions::new("");

    let result = Shield::new().permissions_policy(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}

#[test]
fn given_report_only_configuration_when_secure_then_sets_report_only_header_and_reporting() {
    let group = CspReportGroup::new("pp-group", "https://example.com/reports");
    let options = PermissionsPolicyOptions::new("geolocation=()")
        .report_only()
        .report_group(group.clone())
        .reporting_endpoint("pp-endpoint", "https://example.com/report-endpoint");
    let shield = Shield::new().permissions_policy(options).expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured Report-To group: pp-group")
    }));
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured reporting endpoints: pp-endpoint -> https://example.com/report-endpoint")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::PERMISSIONS_POLICY_REPORT_ONLY)
            .map(String::as_str),
        Some("geolocation=()")
    );

    let expected_report_to = group.header_value();
    assert_eq!(
        result.get(header_keys::REPORT_TO).map(String::as_str),
        Some(expected_report_to.as_str())
    );

    assert_eq!(
        result
            .get(header_keys::REPORTING_ENDPOINTS)
            .map(String::as_str),
        Some("pp-endpoint=\"https://example.com/report-endpoint\"")
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Added Report-To entry: ")
    }));
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry.message.contains("Added Reporting-Endpoints entry: ")
    }));
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "permissions-policy"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted Permissions-Policy-Report-Only header")
    }));
}
