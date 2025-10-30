use super::*;
use crate::executor::FeatureExecutor;
use crate::permissions_policy::PermissionsPolicyOptionsError;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_non_empty_policy_when_validate_options_then_returns_ok() {
        let executor = PermissionsPolicy::new(PermissionsPolicyOptions::new("camera=()"));

        let result = executor.validate_options();

        assert!(result.is_ok());
    }

    #[test]
    fn given_blank_policy_when_validate_options_then_returns_empty_policy_error() {
        let executor = PermissionsPolicy::new(PermissionsPolicyOptions::new("   "));

        let error = executor
            .validate_options()
            .expect_err("expected empty policy error");

        assert_eq!(
            error.to_string(),
            PermissionsPolicyOptionsError::EmptyPolicy.to_string()
        );
    }
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = PermissionsPolicyOptions::new("camera=()");
        let executor = PermissionsPolicy::new(options);

        let result = executor.options();

        let expected = PermissionsPolicyOptions::new("camera=()");
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_permissions_policy_header() {
        let executor = PermissionsPolicy::new(PermissionsPolicyOptions::new("geolocation=()"));
        let mut headers = common::normalized_headers_from(&[("Existing", "header")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Permissions-Policy"),
            Some(&"geolocation=()".to_string())
        );
        assert_eq!(result.get("Existing"), Some(&"header".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_same_header_value() {
        let executor = PermissionsPolicy::new(PermissionsPolicyOptions::new("fullscreen=()"));
        let mut first_headers = common::normalized_headers_from(&[]);
        let mut second_headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut first_headers)
            .expect("first execute should succeed");
        executor
            .execute(&mut second_headers)
            .expect("second execute should succeed");

        let first = first_headers.into_result();
        let second = second_headers.into_result();
        assert_eq!(
            first.get("Permissions-Policy"),
            Some(&"fullscreen=()".to_string())
        );
        assert_eq!(
            second.get("Permissions-Policy"),
            Some(&"fullscreen=()".to_string())
        );
    }

    #[test]
    fn given_report_only_mode_when_execute_then_sets_report_only_and_feature_policy_fallback() {
        let executor =
            PermissionsPolicy::new(PermissionsPolicyOptions::new("camera=()").report_only());
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Permissions-Policy-Report-Only"),
            Some(&"camera=()".to_string())
        );
        assert_eq!(result.get("Feature-Policy"), Some(&"camera=()".to_string()));
        assert!(!result.contains_key("Permissions-Policy"));
    }

    #[test]
    fn given_enforce_mode_when_execute_then_does_not_emit_feature_policy_fallback() {
        let executor = PermissionsPolicy::new(PermissionsPolicyOptions::new("microphone=()"));
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Permissions-Policy"),
            Some(&"microphone=()".to_string())
        );
        assert!(!result.contains_key("Feature-Policy"));
        assert!(!result.contains_key("Permissions-Policy-Report-Only"));
    }
}
