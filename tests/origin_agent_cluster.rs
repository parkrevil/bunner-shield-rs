use bunner_shield_rs::{OriginAgentClusterOptions, Shield, header_keys, header_values};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_oac(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::ORIGIN_AGENT_CLUSTER.to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_enable_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::ORIGIN_AGENT_CLUSTER)
                .map(String::as_str),
            Some(header_values::ORIGIN_AGENT_CLUSTER_ENABLE)
        );
    }

    #[test]
    fn given_disabled_options_when_secure_then_sets_disable_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::ORIGIN_AGENT_CLUSTER)
                .map(String::as_str),
            Some(header_values::ORIGIN_AGENT_CLUSTER_DISABLE)
        );
    }

    #[test]
    fn given_disable_then_enable_when_secure_then_respects_last_override() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable().enable())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::ORIGIN_AGENT_CLUSTER)
                .map(String::as_str),
            Some(header_values::ORIGIN_AGENT_CLUSTER_ENABLE)
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_marker() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("feature");

        let result = shield.secure(with_oac("?1")).expect("secure");

        assert_eq!(
            result
                .get(header_keys::ORIGIN_AGENT_CLUSTER)
                .map(String::as_str),
            Some(header_values::ORIGIN_AGENT_CLUSTER_DISABLE)
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_unchanged() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new())
            .expect("feature");

        let mut headers = with_oac("?0");
        headers.insert("X-Env".to_string(), "prod".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Env").map(String::as_str), Some("prod"));
    }
}
