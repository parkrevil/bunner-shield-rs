use super::*;

mod trusted_types_builder {
    use super::*;

    #[test]
    fn given_policy_when_trusted_types_policy_then_adds_trusted_types_directive() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("valid policy");
        let options = CspOptions::new().trusted_types(|trusted| trusted.policy(policy));
        assert!(options.header_value().contains("trusted-types appPolicy"));
    }

    #[test]
    fn given_none_when_trusted_types_then_sets_none_literal() {
        let options = CspOptions::new().trusted_types(|tt| tt.none());
        assert!(options.header_value().contains("trusted-types 'none'"));
    }
}
