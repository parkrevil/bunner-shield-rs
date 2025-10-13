use super::{PermissionsPolicyOptions, PermissionsPolicyOptionsError};

mod header_value {
    use super::PermissionsPolicyOptions;

    #[test]
    fn given_policy_when_header_value_then_returns_same_value() {
        let options = PermissionsPolicyOptions::new("geolocation=()");

        assert_eq!(options.header_value(), "geolocation=()");
    }
}

mod validate {
    use super::{PermissionsPolicyOptions, PermissionsPolicyOptionsError};
    use crate::executor::FeatureOptions;

    #[test]
    fn given_non_empty_policy_when_validate_then_returns_ok() {
        let options = PermissionsPolicyOptions::new("camera=(self)");

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_empty_policy_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        ));
    }

    #[test]
    fn given_whitespace_policy_when_validate_then_returns_error() {
        let options = PermissionsPolicyOptions::new("   ");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        ));
    }
}
