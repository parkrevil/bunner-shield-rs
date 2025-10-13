use bunner_shield_rs::{ClearSiteDataOptions, Shield, ShieldError, header_keys, header_values};
use std::collections::HashMap;

#[test]
fn given_cache_section_when_secure_then_sets_header() {
    let options = ClearSiteDataOptions::new().cache();
    let shield = Shield::new().clear_site_data(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::CLEAR_SITE_DATA).map(String::as_str),
        Some(header_values::CLEAR_SITE_DATA_CACHE)
    );
}

#[test]
fn given_no_sections_when_add_feature_then_returns_error() {
    let options = ClearSiteDataOptions::new();

    let result = Shield::new().clear_site_data(options);

    match result {
        Err(ShieldError::ExecutorValidationFailed(_)) => {}
        _ => panic!("expected executor validation failure"),
    }
}
