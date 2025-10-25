use super::OriginAgentClusterOptions;
use crate::constants::header_keys::ORIGIN_AGENT_CLUSTER;
use crate::executor::CachedHeader;
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

crate::impl_cached_header_executor!(
    OriginAgentCluster,
    OriginAgentClusterOptions,
    ORIGIN_AGENT_CLUSTER
);

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
