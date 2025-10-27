use bunner_shield_rs::{
    FetchMetadataOptions, FetchMetadataRule, FetchMode, Shield, ShieldError, header_keys,
};
mod common;
use common::headers_with;

#[test]
fn given_cross_site_navigation_when_secure_then_allows_request() {
    let shield = Shield::new()
        .fetch_metadata(FetchMetadataOptions::new())
        .expect("feature");
    let headers = headers_with(&[
        (header_keys::SEC_FETCH_SITE, "cross-site"),
        (header_keys::SEC_FETCH_MODE, "navigate"),
        (header_keys::SEC_FETCH_DEST, "document"),
        (header_keys::SEC_FETCH_USER, "?1"),
    ]);

    let result = shield.secure(headers.clone()).expect("secure");

    assert_eq!(result, headers);
}

#[test]
fn given_cross_site_request_without_allowance_when_secure_then_blocks_request() {
    let shield = Shield::new()
        .fetch_metadata(FetchMetadataOptions::new())
        .expect("feature");
    let headers = headers_with(&[
        (header_keys::SEC_FETCH_SITE, "cross-site"),
        (header_keys::SEC_FETCH_MODE, "cors"),
        (header_keys::SEC_FETCH_DEST, "empty"),
    ]);

    let error = shield
        .secure(headers)
        .expect_err("expected fetch metadata execution failure");

    match error {
        ShieldError::ExecutionFailed(inner) => {
            assert!(inner.to_string().contains("cross-site request blocked"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn given_cross_site_cors_request_with_allow_rule_when_secure_then_allows_request() {
    let options = FetchMetadataOptions::new()
        .allow_cross_site_rule(FetchMetadataRule::new().mode(FetchMode::Cors));
    let shield = Shield::new().fetch_metadata(options).expect("feature");
    let headers = headers_with(&[
        (header_keys::SEC_FETCH_SITE, "cross-site"),
        (header_keys::SEC_FETCH_MODE, "cors"),
        (header_keys::SEC_FETCH_DEST, "empty"),
    ]);

    let result = shield.secure(headers.clone()).expect("secure");

    assert_eq!(result, headers);
}

#[test]
fn given_missing_fetch_metadata_headers_when_secure_and_legacy_disabled_then_blocks() {
    let shield = Shield::new()
        .fetch_metadata(FetchMetadataOptions::new().allow_legacy_clients(false))
        .expect("feature");

    let error = shield
        .secure(headers_with(&[]))
        .expect_err("expected missing header failure");

    match error {
        ShieldError::ExecutionFailed(inner) => {
            assert_eq!(
                inner.to_string(),
                "fetch metadata headers missing (legacy clients are not allowed)"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
