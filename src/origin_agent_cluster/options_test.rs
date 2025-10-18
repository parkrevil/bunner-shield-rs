use super::*;
use crate::constants::header_values::{ORIGIN_AGENT_CLUSTER_DISABLE, ORIGIN_AGENT_CLUSTER_ENABLE};

mod header_value {
    use super::*;

    #[test]
    fn given_default_options_when_header_value_then_returns_enable_constant() {
        let options = OriginAgentClusterOptions::new();

        let value = options.header_value();

        assert_eq!(value, ORIGIN_AGENT_CLUSTER_ENABLE);
    }
}

mod enable_disable {
    use super::*;

    #[test]
    fn given_options_when_enable_then_sets_enable_constant() {
        let options = OriginAgentClusterOptions::new().disable().enable();

        assert_eq!(options.header_value(), ORIGIN_AGENT_CLUSTER_ENABLE);
    }

    #[test]
    fn given_options_when_disable_then_sets_disable_constant() {
        let options = OriginAgentClusterOptions::new().disable();

        assert_eq!(options.header_value(), ORIGIN_AGENT_CLUSTER_DISABLE);
    }
}
