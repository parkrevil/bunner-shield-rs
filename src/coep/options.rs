use crate::constants::header_values::{COEP_CREDENTIALLESS, COEP_REQUIRE_CORP};
use crate::executor::{FeatureOptions, ReportContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoepPolicy {
    RequireCorp,
    Credentialless,
}

impl CoepPolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            CoepPolicy::RequireCorp => COEP_REQUIRE_CORP,
            CoepPolicy::Credentialless => COEP_CREDENTIALLESS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoepOptions {
    pub(crate) policy: CoepPolicy,
}

impl CoepOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy(mut self, policy: CoepPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl Default for CoepOptions {
    fn default() -> Self {
        Self {
            policy: CoepPolicy::RequireCorp,
        }
    }
}

impl FeatureOptions for CoepOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "coep",
            format!(
                "Configured Cross-Origin-Embedder-Policy: {}",
                self.policy.as_str()
            ),
        );
    }
}
