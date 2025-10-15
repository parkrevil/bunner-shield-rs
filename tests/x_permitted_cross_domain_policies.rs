use bunner_shield_rs::{
    Shield, XPermittedCrossDomainPoliciesOptions, XPermittedCrossDomainPoliciesPolicy, header_keys,
    header_values,
};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_none() {
    let shield = Shield::new()
        .x_permitted_cross_domain_policies(XPermittedCrossDomainPoliciesOptions::new())
        .expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-permitted-cross-domain-policies"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Permitted-Cross-Domain-Policies")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_PERMITTED_CROSS_DOMAIN_POLICIES)
            .map(String::as_str),
        Some(header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_NONE)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-permitted-cross-domain-policies"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-Permitted-Cross-Domain-Policies header")
    }));
}

#[test]
fn given_master_only_policy_when_secure_then_sets_master_only() {
    let shield = Shield::new()
        .x_permitted_cross_domain_policies(
            XPermittedCrossDomainPoliciesOptions::new()
                .policy(XPermittedCrossDomainPoliciesPolicy::MasterOnly),
        )
        .expect("feature");
    let headers = HashMap::new();

    let validation_reports = shield.take_report_entries();
    assert!(validation_reports.iter().any(|entry| {
        entry.feature == "x-permitted-cross-domain-policies"
            && entry.kind == bunner_shield_rs::ReportKind::Validation
            && entry
                .message
                .contains("Configured X-Permitted-Cross-Domain-Policies")
    }));

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_PERMITTED_CROSS_DOMAIN_POLICIES)
            .map(String::as_str),
        Some(header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_MASTER_ONLY)
    );

    let runtime_reports = shield.report_entries();
    assert!(runtime_reports.iter().any(|entry| {
        entry.feature == "x-permitted-cross-domain-policies"
            && entry.kind == bunner_shield_rs::ReportKind::Runtime
            && entry
                .message
                .contains("Emitted X-Permitted-Cross-Domain-Policies header")
    }));
}
