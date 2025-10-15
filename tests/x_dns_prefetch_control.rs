use bunner_shield_rs::{
    Shield, XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy, header_keys, header_values,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_prefetch(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::X_DNS_PREFETCH_CONTROL.to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_default_options_when_secure_then_sets_off_policy() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::X_DNS_PREFETCH_CONTROL)
                .map(String::as_str),
            Some(header_values::X_DNS_PREFETCH_CONTROL_OFF)
        );
    }

    #[test]
    fn given_on_policy_when_secure_then_sets_on_value() {
        let shield = Shield::new()
            .x_dns_prefetch_control(
                XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
            )
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::X_DNS_PREFETCH_CONTROL)
                .map(String::as_str),
            Some(header_values::X_DNS_PREFETCH_CONTROL_ON)
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_configured_value() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let result = shield.secure(with_prefetch("on")).expect("secure");

        assert_eq!(
            result
                .get(header_keys::X_DNS_PREFETCH_CONTROL)
                .map(String::as_str),
            Some(header_values::X_DNS_PREFETCH_CONTROL_OFF)
        );
    }

    #[test]
    fn given_other_headers_when_secure_then_keeps_them() {
        let shield = Shield::new()
            .x_dns_prefetch_control(XdnsPrefetchControlOptions::new())
            .expect("feature");

        let mut headers = with_prefetch("on");
        headers.insert("X-Cache".to_string(), "HIT".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Cache").map(String::as_str), Some("HIT"));
    }
}
