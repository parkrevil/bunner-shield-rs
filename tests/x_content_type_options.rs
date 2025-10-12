use bunner_shield_rs::{Shield, header_keys, header_values};
use std::collections::HashMap;

#[test]
fn given_headers_without_nosniff_when_secure_then_sets_header() {
    let shield = Shield::new().x_content_type_options().expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_CONTENT_TYPE_OPTIONS)
            .map(String::as_str),
        Some(header_values::NOSNIFF)
    );
}

#[test]
fn given_existing_header_when_secure_then_overwrites_with_nosniff() {
    let shield = Shield::new().x_content_type_options().expect("feature");
    let mut headers = HashMap::new();
    headers.insert("X-Content-Type-Options".to_string(), "whatever".to_string());

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::X_CONTENT_TYPE_OPTIONS)
            .map(String::as_str),
        Some(header_values::NOSNIFF)
    );
}
