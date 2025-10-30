use super::*;
use crate::constants::header_values::{COEP_CREDENTIALLESS, COEP_REQUIRE_CORP};
use crate::executor::PolicyMode;

mod as_str {
    use super::*;

    #[test]
    fn given_require_corp_policy_when_as_str_then_returns_require_corp_constant() {
        let policy = CoepPolicy::RequireCorp;

        let value = policy.as_str();

        assert_eq!(value, COEP_REQUIRE_CORP);
    }

    #[test]
    fn given_credentialless_policy_when_as_str_then_returns_credentialless_constant() {
        let policy = CoepPolicy::Credentialless;

        let value = policy.as_str();

        assert_eq!(value, COEP_CREDENTIALLESS);
    }
}

mod from_str {
    use super::*;

    #[test]
    fn given_require_corp_text_when_parse_then_returns_require_corp_policy() {
        let policy: CoepPolicy = "require-corp".parse().expect("parse should succeed");

        assert_eq!(policy, CoepPolicy::RequireCorp);
    }

    #[test]
    fn given_credentialless_text_when_parse_then_returns_credentialless_policy() {
        let policy: CoepPolicy = "credentialless".parse().expect("parse should succeed");

        assert_eq!(policy, CoepPolicy::Credentialless);
    }

    #[test]
    fn given_mixed_case_text_when_parse_then_returns_policy_case_insensitively() {
        let policy: CoepPolicy = " ReQuIrE-CoRp ".parse().expect("parse should succeed");

        assert_eq!(policy, CoepPolicy::RequireCorp);
    }

    #[test]
    fn given_unknown_text_when_parse_then_returns_invalid_policy_error() {
        let error = "unknown".parse::<CoepPolicy>().unwrap_err();

        assert_eq!(
            error,
            CoepOptionsError::InvalidPolicy("unknown".to_string())
        );
    }
}

mod new {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_require_corp_policy() {
        let options = CoepOptions::new();

        assert_eq!(options.policy, CoepPolicy::RequireCorp);
        assert_eq!(options.mode(), PolicyMode::Enforce);
    }
}

mod policy {
    use super::*;

    #[test]
    fn given_explicit_policy_when_policy_then_returns_instance_with_policy() {
        let options = CoepOptions::new().policy(CoepPolicy::Credentialless);

        assert_eq!(options.policy, CoepPolicy::Credentialless);
    }

    #[test]
    fn given_text_policy_when_policy_from_str_then_sets_parsed_policy() {
        let options = CoepOptions::new()
            .policy_from_str("credentialless")
            .expect("parse should succeed");

        assert_eq!(options.policy, CoepPolicy::Credentialless);
    }

    #[test]
    fn given_invalid_text_when_policy_from_str_then_returns_invalid_policy_error() {
        let error = CoepOptions::new()
            .policy_from_str("invalid")
            .expect_err("expected invalid policy error");

        assert_eq!(
            error,
            CoepOptionsError::InvalidPolicy("invalid".to_string())
        );
    }

    #[test]
    fn given_policy_str_when_from_policy_str_then_returns_options_with_policy() {
        let options = CoepOptions::from_policy_str("require-corp").expect("parse should succeed");

        assert_eq!(options.policy, CoepPolicy::RequireCorp);
        assert_eq!(options.mode(), PolicyMode::Enforce);
    }
}

mod mode {
    use super::*;

    #[test]
    fn given_options_when_report_only_then_switches_mode_to_report_only() {
        let options = CoepOptions::new().report_only();

        assert_eq!(options.mode(), PolicyMode::ReportOnly);
    }

    #[test]
    fn given_options_when_mode_called_then_returns_current_mode() {
        let options = CoepOptions::new()
            .policy(CoepPolicy::Credentialless)
            .report_only();

        assert_eq!(options.mode(), PolicyMode::ReportOnly);
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = CoepOptions::new().policy(CoepPolicy::Credentialless);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
