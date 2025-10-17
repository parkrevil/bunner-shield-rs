use super::OriginAgentClusterOptions;
use crate::constants::header_keys::ORIGIN_AGENT_CLUSTER;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct OriginAgentCluster {
    cached: CachedHeader<OriginAgentClusterOptions>,
}

impl OriginAgentCluster {
    pub fn new(options: OriginAgentClusterOptions) -> Self {
        let header_value = options.header_value();
        Self {
            cached: CachedHeader::new(options, Cow::Borrowed(header_value)),
        }
    }
}

impl FeatureExecutor for OriginAgentCluster {
    type Options = OriginAgentClusterOptions;

    fn options(&self) -> &Self::Options {
        self.cached.options()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(ORIGIN_AGENT_CLUSTER, self.cached.cloned_header_value());

        Ok(())
    }
}
