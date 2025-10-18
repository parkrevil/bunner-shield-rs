use super::*;
use crate::constants::header_values::{CORP_CROSS_ORIGIN, CORP_SAME_ORIGIN, CORP_SAME_SITE};

mod policy_as_str {
    use super::*;

    #[test]
    fn given_same_origin_policy_when_as_str_then_returns_same_origin_constant() {
        let policy = CorpPolicy::SameOrigin;

        let value = policy.as_str();

        assert_eq!(value, CORP_SAME_ORIGIN);
    }

    #[test]
    fn given_same_site_policy_when_as_str_then_returns_same_site_constant() {
        let policy = CorpPolicy::SameSite;

        let value = policy.as_str();

        assert_eq!(value, CORP_SAME_SITE);
    }

    #[test]
    fn given_cross_origin_policy_when_as_str_then_returns_cross_origin_constant() {
        let policy = CorpPolicy::CrossOrigin;

        let value = policy.as_str();

        assert_eq!(value, CORP_CROSS_ORIGIN);
    }
}

mod policy_from_str {
    use super::*;

    #[test]
    fn given_same_origin_text_when_parse_then_returns_same_origin_policy() {
        let policy: CorpPolicy = "same-origin".parse().expect("parse should succeed");

        assert_eq!(policy, CorpPolicy::SameOrigin);
    }

    #[test]
    fn given_same_site_text_when_parse_then_returns_same_site_policy() {
        let policy: CorpPolicy = "same-site".parse().expect("parse should succeed");

        assert_eq!(policy, CorpPolicy::SameSite);
    }

    #[test]
    fn given_cross_origin_text_when_parse_then_returns_cross_origin_policy() {
        let policy: CorpPolicy = "cross-origin".parse().expect("parse should succeed");

        assert_eq!(policy, CorpPolicy::CrossOrigin);
    }

    #[test]
    fn given_trimmed_mixed_case_text_when_parse_then_returns_policy_case_insensitively() {
        let policy: CorpPolicy = "  SaMe-SiTe  ".parse().expect("parse should succeed");

        assert_eq!(policy, CorpPolicy::SameSite);
    }

    #[test]
    fn given_unknown_text_when_parse_then_returns_invalid_policy_error() {
        let error = "unknown".parse::<CorpPolicy>().unwrap_err();

        assert_eq!(
            error,
            CorpOptionsError::InvalidPolicy("unknown".to_string())
        );
    }
}

mod options_default {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_same_origin_policy() {
        let options = CorpOptions::new();

        assert_eq!(options.policy, CorpPolicy::SameOrigin);
    }
}

mod options_builder {
    use super::*;

    #[test]
    fn given_explicit_policy_when_policy_then_sets_policy_on_builder() {
        let options = CorpOptions::new().policy(CorpPolicy::CrossOrigin);

        assert_eq!(options.policy, CorpPolicy::CrossOrigin);
    }

    #[test]
    fn given_policy_text_when_policy_from_str_then_updates_to_parsed_policy() {
        let options = CorpOptions::new()
            .policy_from_str("same-site")
            .expect("parse should succeed");

        assert_eq!(options.policy, CorpPolicy::SameSite);
    }

    #[test]
    fn given_invalid_text_when_policy_from_str_then_returns_invalid_policy_error() {
        let error = CorpOptions::new()
            .policy_from_str("bad")
            .expect_err("expected invalid policy error");

        assert_eq!(error, CorpOptionsError::InvalidPolicy("bad".to_string()));
    }

    #[test]
    fn given_policy_text_when_from_policy_str_then_creates_options_with_policy() {
        let options = CorpOptions::from_policy_str("cross-origin").expect("parse should succeed");

        assert_eq!(options.policy, CorpPolicy::CrossOrigin);
    }

    #[test]
    fn given_invalid_text_when_from_policy_str_then_returns_invalid_policy_error() {
        let error =
            CorpOptions::from_policy_str("invalid").expect_err("expected invalid policy error");

        assert_eq!(
            error,
            CorpOptionsError::InvalidPolicy("invalid".to_string())
        );
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = CorpOptions::new().policy(CorpPolicy::CrossOrigin);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
