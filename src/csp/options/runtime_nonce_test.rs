use super::*;
use crate::csp::options::nonce::CspNonceManager;

mod runtime_nonce {
    use super::*;

    #[test]
    fn given_runtime_nonce_config_when_allocate_and_issue_then_returns_token_and_value() {
        let mut config = RuntimeNonceConfig::with_manager(CspNonceManager::new());
        config.record_directive("script-src", config.allocate_placeholder());

        let placeholder = config
            .directives()
            .find(|(d, _)| d.as_str() == "script-src")
            .map(|(_, t)| t.clone())
            .expect("placeholder exists");
        assert!(placeholder.starts_with("'nonce-"));

        let runtime_value = config.issue_runtime_value();
        assert!(!runtime_value.is_empty());
    }
}
