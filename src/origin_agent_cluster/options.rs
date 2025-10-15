use crate::constants::header_values::{ORIGIN_AGENT_CLUSTER_DISABLE, ORIGIN_AGENT_CLUSTER_ENABLE};
use crate::executor::{FeatureOptions, ReportContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginAgentClusterOptions {
    pub(crate) enabled: &'static str,
}

impl OriginAgentClusterOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable(mut self) -> Self {
        self.enabled = ORIGIN_AGENT_CLUSTER_ENABLE;
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = ORIGIN_AGENT_CLUSTER_DISABLE;
        self
    }

    pub(crate) fn header_value(&self) -> &'static str {
        self.enabled
    }
}

impl Default for OriginAgentClusterOptions {
    fn default() -> Self {
        Self {
            enabled: ORIGIN_AGENT_CLUSTER_ENABLE,
        }
    }
}

impl FeatureOptions for OriginAgentClusterOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "origin-agent-cluster",
            format!(
                "Configured Origin-Agent-Cluster header value: {}",
                self.enabled
            ),
        );
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
