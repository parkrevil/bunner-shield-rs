use super::nonce::{CspNonce, CspNonceManager};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

pub(crate) trait NonceStrategy: Send + Sync {
    fn issue(&self) -> CspNonce;
    fn clone_box(&self) -> Box<dyn NonceStrategy>;
}

#[derive(Debug, Clone, Default)]
struct DefaultNonceStrategy {
    manager: CspNonceManager,
}

impl DefaultNonceStrategy {
    fn new(manager: CspNonceManager) -> Self {
        Self { manager }
    }
}

impl NonceStrategy for DefaultNonceStrategy {
    fn issue(&self) -> CspNonce {
        self.manager.issue()
    }

    fn clone_box(&self) -> Box<dyn NonceStrategy> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn NonceStrategy> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeNonceConfig {
    strategy: Arc<dyn NonceStrategy>,
    directives: HashMap<String, String>,
}

impl fmt::Debug for RuntimeNonceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeNonceConfig")
            .field("directives", &self.directives)
            .finish()
    }
}

impl RuntimeNonceConfig {
    pub(crate) fn new() -> Self {
        Self {
            strategy: Arc::new(DefaultNonceStrategy::default()),
            directives: HashMap::new(),
        }
    }

    pub(crate) fn with_manager(manager: CspNonceManager) -> Self {
        Self {
            strategy: Arc::new(DefaultNonceStrategy::new(manager)),
            directives: HashMap::new(),
        }
    }

    pub(crate) fn set_manager(&mut self, manager: CspNonceManager) {
        self.strategy = Arc::new(DefaultNonceStrategy::new(manager));
    }

    pub(crate) fn record_directive(&mut self, directive: &str, token: String) {
        self.directives
            .entry(directive.to_string())
            .or_insert(token);
    }

    pub(crate) fn adopt_strategy(&mut self, other: &RuntimeNonceConfig) {
        self.strategy = other.strategy.clone();
    }

    pub(crate) fn merge(&mut self, other: &RuntimeNonceConfig) {
        for (name, token) in &other.directives {
            self.directives.entry(name.clone()).or_insert(token.clone());
        }
    }

    pub(crate) fn directives(&self) -> impl Iterator<Item = (&String, &String)> {
        self.directives.iter()
    }

    pub(crate) fn allocate_placeholder(&self) -> String {
        self.strategy.issue().header_value()
    }

    pub(crate) fn issue_runtime_value(&self) -> String {
        self.strategy.issue().into_inner()
    }

    pub(crate) fn has_directive(&self, directive: &str) -> bool {
        self.directives.contains_key(directive)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }
}

#[cfg(test)]
#[path = "runtime_nonce_test.rs"]
mod runtime_nonce_test;
