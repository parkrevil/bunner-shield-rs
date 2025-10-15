use bunner_shield_rs::{Shield, XFrameOptionsOptions, XFrameOptionsPolicy, header_keys};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_xfo(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(header_keys::X_FRAME_OPTIONS.to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_deny() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
            Some("DENY")
        );
    }

    #[test]
    fn given_same_origin_policy_when_secure_then_sets_sameorigin() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
            Some("SAMEORIGIN")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_configured_policy() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let result = shield.secure(with_xfo("ALLOW")).expect("secure");

        assert_eq!(
            result.get(header_keys::X_FRAME_OPTIONS).map(String::as_str),
            Some("DENY")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_intact() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new())
            .expect("feature");

        let mut headers = with_xfo("ALLOW");
        headers.insert("X-Trace".to_string(), "abc".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Trace").map(String::as_str), Some("abc"));
    }
}
