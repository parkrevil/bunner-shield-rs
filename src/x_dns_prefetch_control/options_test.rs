use super::*;
use crate::constants::header_values as values;

mod policy_as_str {
    use super::*;

    #[test]
    fn given_on_policy_when_as_str_then_returns_on_constant() {
        assert_eq!(
            XdnsPrefetchControlPolicy::On.as_str(),
            values::X_DNS_PREFETCH_CONTROL_ON
        );
    }

    #[test]
    fn given_off_policy_when_as_str_then_returns_off_constant() {
        assert_eq!(
            XdnsPrefetchControlPolicy::Off.as_str(),
            values::X_DNS_PREFETCH_CONTROL_OFF
        );
    }
}

mod defaults {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_off_policy() {
        let options = XdnsPrefetchControlOptions::new();

        assert_eq!(options.policy, XdnsPrefetchControlPolicy::Off);
    }
}

mod builder {
    use super::*;

    #[test]
    fn given_policy_when_policy_then_updates_policy_field() {
        let options = XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On);

        assert_eq!(options.policy, XdnsPrefetchControlPolicy::On);
    }
}

mod header_value {
    use super::*;

    #[test]
    fn given_options_when_header_value_then_returns_policy_constant() {
        let options = XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On);

        assert_eq!(options.header_value(), values::X_DNS_PREFETCH_CONTROL_ON);
    }
}

mod validation {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = XdnsPrefetchControlOptions::new();

        assert!(options.validate().is_ok());
    }
}
