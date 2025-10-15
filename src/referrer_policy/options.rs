use crate::constants::header_values::{
    REFERRER_POLICY_NO_REFERRER, REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE,
    REFERRER_POLICY_ORIGIN, REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN, REFERRER_POLICY_SAME_ORIGIN,
    REFERRER_POLICY_STRICT_ORIGIN, REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
    REFERRER_POLICY_UNSAFE_URL,
};
use crate::executor::{FeatureOptions, ReportContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicyValue {
    NoReferrer,
    NoReferrerWhenDowngrade,
    SameOrigin,
    Origin,
    StrictOrigin,
    OriginWhenCrossOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicyValue {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ReferrerPolicyValue::NoReferrer => REFERRER_POLICY_NO_REFERRER,
            ReferrerPolicyValue::NoReferrerWhenDowngrade => {
                REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE
            }
            ReferrerPolicyValue::SameOrigin => REFERRER_POLICY_SAME_ORIGIN,
            ReferrerPolicyValue::Origin => REFERRER_POLICY_ORIGIN,
            ReferrerPolicyValue::StrictOrigin => REFERRER_POLICY_STRICT_ORIGIN,
            ReferrerPolicyValue::OriginWhenCrossOrigin => REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN,
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin => {
                REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN
            }
            ReferrerPolicyValue::UnsafeUrl => REFERRER_POLICY_UNSAFE_URL,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferrerPolicyOptions {
    pub(crate) policy: ReferrerPolicyValue,
}

impl ReferrerPolicyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: ReferrerPolicyValue) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn header_value(&self) -> &'static str {
        self.policy.as_str()
    }
}

impl Default for ReferrerPolicyOptions {
    fn default() -> Self {
        Self {
            policy: ReferrerPolicyValue::StrictOriginWhenCrossOrigin,
        }
    }
}

impl FeatureOptions for ReferrerPolicyOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "referrer-policy",
            format!("Configured Referrer-Policy: {}", self.policy.as_str()),
        );
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
