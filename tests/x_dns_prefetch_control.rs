use bunner_shield_rs::{
    Shield, XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy, header_keys, header_values,
};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_off() {
    let shield = Shield::new()
        .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
        .expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-dns-prefetch-control"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-DNS-Prefetch-Control policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_DNS_PREFETCH_CONTROL)
            .map(String::as_str),
        Some(header_values::X_DNS_PREFETCH_CONTROL_OFF)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-dns-prefetch-control"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-DNS-Prefetch-Control header")
    }));
}

#[test]
fn given_on_policy_when_secure_then_sets_on() {
    let shield = Shield::new()
        .x_dns_prefetch_control(
            XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
        )
        .expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-dns-prefetch-control"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-DNS-Prefetch-Control policy")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_DNS_PREFETCH_CONTROL)
            .map(String::as_str),
        Some(header_values::X_DNS_PREFETCH_CONTROL_ON)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-dns-prefetch-control"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-DNS-Prefetch-Control header")
    }));
}
