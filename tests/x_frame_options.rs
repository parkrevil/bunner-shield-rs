use bunner_shield_rs::{Shield, XFrameOptionsOptions, XFrameOptionsPolicy, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_deny() {
    let options = XFrameOptionsOptions::new();
    let shield = Shield::new().x_frame_options(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
        Some("DENY")
    );
}

#[test]
fn given_same_origin_policy_when_secure_then_sets_sameorigin() {
    let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);
    let shield = Shield::new().x_frame_options(options).expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
        Some("SAMEORIGIN")
    );
}
