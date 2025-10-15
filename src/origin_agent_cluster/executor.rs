use super::OriginAgentClusterOptions;
use crate::constants::header_keys::ORIGIN_AGENT_CLUSTER;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct OriginAgentCluster {
    options: OriginAgentClusterOptions,
}

impl OriginAgentCluster {
    pub fn new(options: OriginAgentClusterOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for OriginAgentCluster {
    type Options = OriginAgentClusterOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(ORIGIN_AGENT_CLUSTER, self.options.header_value());

        Ok(())
    }
}
