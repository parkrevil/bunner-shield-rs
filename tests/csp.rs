use bunner_shield_rs::{CspOptions, CspReportGroup, CspSource, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_enforced_policy_when_secure_then_applies_csp_header() {
    let policy = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .base_uri([CspSource::None])
        .frame_ancestors([CspSource::None]);
    let shield = Shield::new().csp(policy).expect("feature");
    let mut headers = HashMap::new();
    headers.insert("X-Request-Id".to_string(), "abc-123".to_string());

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CONTENT_SECURITY_POLICY)
            .map(String::as_str),
        Some("default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
    );
    assert_eq!(
        result.get("X-Request-Id").map(String::as_str),
        Some("abc-123")
    );
}

#[test]
fn given_report_only_policy_when_secure_then_emits_report_headers() {
    let report_group = CspReportGroup::new("default", "https://reports.example.com");
    let policy = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .script_src([CspSource::UnsafeInline])
        .report_only()
        .report_group(report_group.clone());
    let shield = Shield::new().csp(policy).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::CONTENT_SECURITY_POLICY_REPORT_ONLY)
            .map(String::as_str),
        Some("default-src 'self'; script-src 'unsafe-inline'; report-to default")
    );
    assert_eq!(
        result.get(header_keys::REPORT_TO).map(String::as_str),
        Some(report_group.header_value().as_str())
    );
}

#[test]
fn given_reporting_endpoints_when_secure_then_emits_reporting_header() {
    let policy = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .reporting_endpoint("default", "https://reports.example.com");
    let shield = Shield::new().csp(policy).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::REPORTING_ENDPOINTS)
            .map(String::as_str),
        Some("default=\"https://reports.example.com\"")
    );
}
