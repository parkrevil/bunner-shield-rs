use bunner_shield_rs::{
    PermissionsPolicyOptions, PermissionsPolicyOptionsError, Shield, ShieldError,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_permissions_policy(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Permissions-Policy".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_policy_when_secure_then_sets_permissions_policy_header() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("geolocation=()")
        );
    }

    #[test]
    fn given_policy_override_when_secure_then_applies_latest_value() {
        let options = PermissionsPolicyOptions::new("geolocation=()").policy("microphone=('self')");
        let shield = Shield::new().permissions_policy(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("microphone=('self')")
        );
    }

    #[test]
    fn given_multiple_features_when_secure_then_preserves_permissions_policy_formatting() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("camera=()"))
            .expect("feature")
            .x_content_type_options()
            .expect("xcto");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("camera=()")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_permissions_policy() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("camera=()"))
            .expect("feature");

        let result = shield
            .secure(with_permissions_policy("geolocation=()*"))
            .expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("camera=()")
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_intact() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("feature");

        let mut headers = with_permissions_policy("camera=()");
        headers.insert("X-Other".to_string(), "value".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Other").map(String::as_str), Some("value"));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(
        result: Result<Shield, ShieldError>,
    ) -> PermissionsPolicyOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<PermissionsPolicyOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_empty_policy_when_add_feature_then_returns_empty_policy_error() {
        let error = expect_validation_error(
            Shield::new().permissions_policy(PermissionsPolicyOptions::new("")),
        );

        assert!(matches!(error, PermissionsPolicyOptionsError::EmptyPolicy));
    }

    #[test]
    fn given_whitespace_policy_when_add_feature_then_returns_empty_policy_error() {
        let error = expect_validation_error(
            Shield::new().permissions_policy(PermissionsPolicyOptions::new("   \t  ")),
        );

        assert!(matches!(error, PermissionsPolicyOptionsError::EmptyPolicy));
    }
}
