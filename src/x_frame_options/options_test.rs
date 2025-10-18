use super::*;
use crate::constants::header_values as values;

mod policy_as_str {
    use super::*;

    #[test]
    fn given_deny_policy_when_as_str_then_returns_deny_constant() {
        assert_eq!(
            XFrameOptionsPolicy::Deny.as_str(),
            values::X_FRAME_OPTIONS_DENY
        );
    }

    #[test]
    fn given_same_origin_policy_when_as_str_then_returns_same_origin_constant() {
        assert_eq!(
            XFrameOptionsPolicy::SameOrigin.as_str(),
            values::X_FRAME_OPTIONS_SAMEORIGIN
        );
    }
}

mod defaults {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_deny_policy() {
        let options = XFrameOptionsOptions::new();

        assert_eq!(options.policy, XFrameOptionsPolicy::Deny);
    }
}

mod builder {
    use super::*;

    #[test]
    fn given_policy_when_policy_then_updates_policy_field() {
        let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);

        assert_eq!(options.policy, XFrameOptionsPolicy::SameOrigin);
    }
}

mod header_value {
    use super::*;

    #[test]
    fn given_options_when_header_value_then_returns_policy_constant() {
        let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);

        assert_eq!(options.header_value(), values::X_FRAME_OPTIONS_SAMEORIGIN);
    }
}

mod validation {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = XFrameOptionsOptions::new();

        assert!(options.validate().is_ok());
    }
}
