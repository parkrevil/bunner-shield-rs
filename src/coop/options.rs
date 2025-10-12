use crate::constants::header_values::{
    COOP_SAME_ORIGIN, COOP_SAME_ORIGIN_ALLOW_POPUPS, COOP_UNSAFE_NONE,
};
use crate::executor::FeatureOptions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoopPolicy {
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone,
}

impl CoopPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoopPolicy::SameOrigin => COOP_SAME_ORIGIN,
            CoopPolicy::SameOriginAllowPopups => COOP_SAME_ORIGIN_ALLOW_POPUPS,
            CoopPolicy::UnsafeNone => COOP_UNSAFE_NONE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoopOptions {
    pub(crate) policy: CoopPolicy,
}

impl CoopOptions {
    pub fn new() -> Self {
        Self {
            policy: CoopPolicy::SameOrigin,
        }
    }

    pub fn policy(mut self, policy: CoopPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl Default for CoopOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureOptions for CoopOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
