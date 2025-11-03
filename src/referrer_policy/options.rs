use crate::constants::header_values::{
    REFERRER_POLICY_NO_REFERRER, REFERRER_POLICY_NO_REFERRER_WHEN_DOWNGRADE,
    REFERRER_POLICY_ORIGIN, REFERRER_POLICY_ORIGIN_WHEN_CROSS_ORIGIN, REFERRER_POLICY_SAME_ORIGIN,
    REFERRER_POLICY_STRICT_ORIGIN, REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
    REFERRER_POLICY_UNSAFE_URL,
};
use crate::executor::FeatureOptions;
use std::borrow::Cow;

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
    fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerPolicyOptions {
    pub(crate) policies: Vec<ReferrerPolicyValue>,
}

impl ReferrerPolicyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: ReferrerPolicyValue) -> Self {
        self.policies = vec![policy];
        self
    }

    pub fn policies<I>(mut self, policies: I) -> Self
    where
        I: IntoIterator<Item = ReferrerPolicyValue>,
    {
        self.policies = policies.into_iter().collect();
        self
    }

    pub(crate) fn header_value(&self) -> Cow<'static, str> {
        match self.policies.as_slice() {
            [single] => Cow::Borrowed(single.as_str()),
            many if !many.is_empty() => {
                let joined = many
                    .iter()
                    .map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                Cow::Owned(joined)
            }
            _ => Cow::Borrowed(ReferrerPolicyValue::StrictOriginWhenCrossOrigin.as_str()),
        }
    }
}

impl Default for ReferrerPolicyOptions {
    fn default() -> Self {
        Self {
            policies: vec![ReferrerPolicyValue::StrictOriginWhenCrossOrigin],
        }
    }
}

impl FeatureOptions for ReferrerPolicyOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
