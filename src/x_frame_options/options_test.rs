use super::*;

mod policy {
    use super::*;

    #[test]
    fn given_default_options_when_header_value_then_returns_deny() {
        let options = XFrameOptionsOptions::new();

        assert_eq!(options.header_value(), "DENY");
    }

    #[test]
    fn given_same_origin_policy_when_header_value_then_returns_sameorigin() {
        let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);

        assert_eq!(options.header_value(), "SAMEORIGIN");
    }
}
