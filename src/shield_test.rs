use super::*;
use crate::csp::CspOptions;
use crate::tests_common as common;

mod new {
    use super::*;

    #[test]
    fn given_new_shield_when_secure_then_returns_original_headers() {
        let shield = Shield::new();
        let headers = common::headers_with(&[("X-App", "1")]);

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result, headers);
    }
}

mod x_powered_by_feature {
    use super::*;

    #[test]
    fn given_x_powered_by_header_when_feature_applied_then_removes_header() {
        let shield = Shield::new().x_powered_by().expect("feature");
        let headers = common::headers_with(&[("X-Powered-By", "Rocket"), ("X-App", "1")]);

        let result = shield.secure(headers).expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
        assert_eq!(result.get("X-App").map(String::as_str), Some("1"));
    }
}

mod multi_feature_pipeline {
    use super::*;

    #[test]
    fn given_multiple_features_when_secure_then_applies_in_configured_order() {
        let shield = Shield::new()
            .x_content_type_options()
            .expect("feature")
            .x_powered_by()
            .expect("feature");
        let headers = common::headers_with(&[("X-Powered-By", "Rocket")]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
        assert!(!result.contains_key("X-Powered-By"));
    }
}

mod validation_failure {
    use super::*;

    #[test]
    fn given_invalid_options_when_feature_added_then_returns_executor_validation_error() {
        let error = Shield::new().csp(CspOptions::new());

        match error {
            Err(ShieldError::ExecutorValidationFailed(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected validation failure"),
        }
    }
}
