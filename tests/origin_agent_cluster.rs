use bunner_shield_rs::{OriginAgentClusterOptions, Shield, header_keys};
use std::collections::HashMap;

#[test]
fn given_default_options_when_secure_then_sets_enable_marker() {
    let options = OriginAgentClusterOptions::new();
    let shield = Shield::new()
        .origin_agent_cluster(options)
        .expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::ORIGIN_AGENT_CLUSTER)
            .map(String::as_str),
        Some("?1")
    );
}

#[test]
fn given_disabled_options_when_secure_then_sets_disable_marker() {
    let options = OriginAgentClusterOptions::new().disable();
    let shield = Shield::new()
        .origin_agent_cluster(options)
        .expect("feature");
    let headers = HashMap::new();

    let result = shield.secure(headers).expect("secure");

    assert_eq!(
        result
            .get(header_keys::ORIGIN_AGENT_CLUSTER)
            .map(String::as_str),
        Some("?0")
    );
}
