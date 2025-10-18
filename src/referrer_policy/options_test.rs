use super::*;
use crate::constants::header_values as values;

mod value_as_str {
    use super::*;

    #[test]
    fn given_no_referrer_value_when_as_str_then_returns_no_referrer_constant() {
        let value = ReferrerPolicyValue::NoReferrer;

        assert_eq!(value.as_str(), values::REFERRER_POLICY_NO_REFERRER);
    }

    #[test]
    fn given_strict_origin_when_cross_origin_value_when_as_str_then_returns_expected_constant() {
        let value = ReferrerPolicyValue::StrictOriginWhenCrossOrigin;

        assert_eq!(
            value.as_str(),
            values::REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN
        );
    }

    #[test]
    fn given_unsafe_url_value_when_as_str_then_returns_unsafe_url_constant() {
        let value = ReferrerPolicyValue::UnsafeUrl;

        assert_eq!(value.as_str(), values::REFERRER_POLICY_UNSAFE_URL);
    }
}

mod defaults {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_strict_origin_when_cross_origin() {
        let options = ReferrerPolicyOptions::new();

        assert_eq!(
            options.policy,
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin
        );
    }
}

mod builder {
    use super::*;

    #[test]
    fn given_explicit_policy_when_policy_then_updates_policy_field() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::NoReferrer);

        assert_eq!(options.policy, ReferrerPolicyValue::NoReferrer);
    }
}

mod header_value {
    use super::*;

    #[test]
    fn given_options_when_header_value_then_returns_policy_constant() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::Origin);

        let value = options.header_value();

        assert_eq!(value, values::REFERRER_POLICY_ORIGIN);
    }
}

mod validation {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::SameOrigin);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
