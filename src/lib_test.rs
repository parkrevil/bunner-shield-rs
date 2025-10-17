use super::*;
use crate::tests_common as common;

mod shield_reexports {
    use super::*;

    #[test]
    fn given_reexported_shield_when_constructed_then_supports_feature_chaining() {
        let shield = Shield::new().x_powered_by().expect("feature");
        let headers = common::headers_with(&[("X-Powered-By", "Rocket")]);

        let result = shield.secure(headers).expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
    }
}

mod constants_reexports {
    use super::*;

    #[test]
    fn given_header_keys_when_accessed_via_crate_then_match_expected_value() {
        assert_eq!(
            header_keys::CONTENT_SECURITY_POLICY,
            "Content-Security-Policy"
        );
    }
}
