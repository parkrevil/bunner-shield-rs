use super::{XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy};

mod header_value {
    use super::{XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy};

    #[test]
    fn given_default_options_when_header_value_then_returns_off() {
        let options = XdnsPrefetchControlOptions::new();

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_DNS_PREFETCH_CONTROL_OFF
        );
    }

    #[test]
    fn given_on_policy_when_header_value_then_returns_on() {
        let options = XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On);

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_DNS_PREFETCH_CONTROL_ON
        );
    }
}
