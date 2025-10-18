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

mod enable {
    use super::*;

    #[test]
    fn given_options_when_enable_then_sets_enable_constant() {
        let options = OriginAgentClusterOptions::new().disable().enable();

        assert_eq!(options.header_value(), ORIGIN_AGENT_CLUSTER_ENABLE);
    }
}

mod disable {
    use super::*;

    #[test]
    fn given_options_when_disable_then_sets_disable_constant() {
        let options = OriginAgentClusterOptions::new().disable();

        assert_eq!(options.header_value(), ORIGIN_AGENT_CLUSTER_DISABLE);
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = OriginAgentClusterOptions::new().disable();

        let result = options.validate();

        assert!(result.is_ok());
    }
}
