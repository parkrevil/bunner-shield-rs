use super::*;

mod new {
    use super::*;

    #[test]
    fn given_valid_name_when_new_then_returns_policy_instance() {
        let policy = TrustedTypesPolicy::new("trustedPolicy").expect("policy should be valid");
        assert_eq!(policy.as_str(), "trustedPolicy");
    }

    #[test]
    fn given_empty_name_when_new_then_returns_empty_error() {
        let error = TrustedTypesPolicy::new("").expect_err("expected empty error");
        assert_eq!(error, TrustedTypesPolicyError::Empty);
    }

    #[test]
    fn given_invalid_characters_when_new_then_returns_invalid_name_error() {
        let error = TrustedTypesPolicy::new("1policy").expect_err("expected invalid name error");
        assert_eq!(
            error,
            TrustedTypesPolicyError::InvalidName("1policy".to_string())
        );
    }
}

mod into_string {
    use super::*;

    #[test]
    fn given_allow_duplicates_token_when_into_string_then_returns_literal() {
        let token = TrustedTypesToken::allow_duplicates();
        assert_eq!(token.into_string(), "'allow-duplicates'");
    }

    #[test]
    fn given_policy_token_when_into_string_then_returns_policy_name() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("policy should be valid");
        let token = TrustedTypesToken::from(policy);
        assert_eq!(token.into_string(), "appPolicy");
    }
}
