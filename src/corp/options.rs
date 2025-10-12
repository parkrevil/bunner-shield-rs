use crate::constants::header_values::{CORP_CROSS_ORIGIN, CORP_SAME_ORIGIN, CORP_SAME_SITE};
use crate::executor::FeatureOptions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpPolicy {
    SameOrigin,
    SameSite,
    CrossOrigin,
}

impl CorpPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CorpPolicy::SameOrigin => CORP_SAME_ORIGIN,
            CorpPolicy::SameSite => CORP_SAME_SITE,
            CorpPolicy::CrossOrigin => CORP_CROSS_ORIGIN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpOptions {
    pub(crate) policy: CorpPolicy,
}

impl CorpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CorpPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl Default for CorpOptions {
    fn default() -> Self {
        Self {
            policy: CorpPolicy::SameOrigin,
        }
    }
}

impl FeatureOptions for CorpOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
