use super::*;

mod new {
    use super::*;

    #[test]
    fn given_initial_policy_when_new_then_stores_policy_string() {
        let options = PermissionsPolicyOptions::new("accelerometer=()");

        assert_eq!(options.header_value(), "accelerometer=()");
    }
}

mod policy {
    use super::*;

    #[test]
    fn given_existing_options_when_policy_then_updates_policy_string() {
        let options = PermissionsPolicyOptions::new("camera=() ").policy("camera=()");

        assert_eq!(options.header_value(), "camera=()");
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_non_empty_policy_when_validate_then_returns_ok() {
        let options = PermissionsPolicyOptions::new("fullscreen=(self)");

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_empty_policy_when_validate_then_returns_empty_policy_error() {
        let options = PermissionsPolicyOptions::new("   ");

        let error = options.validate().expect_err("expected empty policy error");

        assert_eq!(error, PermissionsPolicyOptionsError::EmptyPolicy);
    }
}
