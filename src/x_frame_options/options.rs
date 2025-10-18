use crate::constants::header_values::{X_FRAME_OPTIONS_DENY, X_FRAME_OPTIONS_SAMEORIGIN};
use crate::executor::FeatureOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XFrameOptionsPolicy {
    Deny,
    SameOrigin,
}

impl XFrameOptionsPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            XFrameOptionsPolicy::Deny => X_FRAME_OPTIONS_DENY,
            XFrameOptionsPolicy::SameOrigin => X_FRAME_OPTIONS_SAMEORIGIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XFrameOptionsOptions {
    pub(crate) policy: XFrameOptionsPolicy,
}

impl XFrameOptionsOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: XFrameOptionsPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn header_value(&self) -> &'static str {
        self.policy.as_str()
    }
}

impl Default for XFrameOptionsOptions {
    fn default() -> Self {
        Self {
            policy: XFrameOptionsPolicy::Deny,
        }
    }
}

impl FeatureOptions for XFrameOptionsOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
