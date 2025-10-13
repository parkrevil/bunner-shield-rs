use super::*;

mod header_value {
    use super::*;

    #[test]
    fn given_default_options_when_header_value_then_returns_strict_origin_when_cross_origin() {
        let options = ReferrerPolicyOptions::new();

        assert_eq!(options.header_value(), "strict-origin-when-cross-origin");
    }

    #[test]
    fn given_custom_policy_when_header_value_then_returns_configured_value() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::NoReferrer);

        assert_eq!(options.header_value(), "no-referrer");
    }
}
