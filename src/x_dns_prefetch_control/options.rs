use crate::constants::header_values::{X_DNS_PREFETCH_CONTROL_OFF, X_DNS_PREFETCH_CONTROL_ON};
use crate::executor::FeatureOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdnsPrefetchControlPolicy {
    On,
    Off,
}

impl XdnsPrefetchControlPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            XdnsPrefetchControlPolicy::On => X_DNS_PREFETCH_CONTROL_ON,
            XdnsPrefetchControlPolicy::Off => X_DNS_PREFETCH_CONTROL_OFF,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdnsPrefetchControlOptions {
    policy: XdnsPrefetchControlPolicy,
}

impl XdnsPrefetchControlOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: XdnsPrefetchControlPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn header_value(&self) -> &'static str {
        self.policy.as_str()
    }
}

impl Default for XdnsPrefetchControlOptions {
    fn default() -> Self {
        Self {
            policy: XdnsPrefetchControlPolicy::Off,
        }
    }
}

impl FeatureOptions for XdnsPrefetchControlOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
