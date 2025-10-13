use super::*;

mod header_value {
    use super::*;

    #[test]
    fn given_default_options_when_header_value_then_returns_enabled_marker() {
        let options = OriginAgentClusterOptions::new();

        assert_eq!(options.header_value(), "?1");
    }

    #[test]
    fn given_disabled_options_when_header_value_then_returns_disabled_marker() {
        let options = OriginAgentClusterOptions::new().disable();

        assert_eq!(options.header_value(), "?0");
    }
}
