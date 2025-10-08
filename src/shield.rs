use crate::constants::executor_order::CONTENT_SECURITY_POLICY;
use crate::csp::{Csp, CspOptions};
use crate::executor::Executor;
use crate::normalized_headers::NormalizedHeaders;
use thiserror::Error;

type ShieldExecutor = Box<dyn Executor<Output = Vec<(String, String)>> + 'static>;

struct PipelineEntry {
    order: u8,
    executor: ShieldExecutor,
}

#[derive(Default)]
pub struct Shield {
    pipeline: Vec<PipelineEntry>,
}

impl Shield {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_feature(mut self, order: u8, executor: ShieldExecutor) -> Result<Self, ShieldError> {
        executor
            .validate_options()
            .map_err(ShieldError::ExecutorValidationFailed)?;

        self.pipeline.push(PipelineEntry { order, executor });
        self.pipeline.sort_by(|a, b| a.order.cmp(&b.order));

        Ok(self)
    }

    pub fn secure(&self, mut headers: Vec<(String, String)>) -> Result<NormalizedHeaders, ShieldError> {
        for entry in &self.pipeline {
            headers.extend(entry.executor.execute());
        }

        Ok(NormalizedHeaders::from_pairs(headers))
    }

    pub fn content_security_policy(self, options: CspOptions) -> Result<Self, ShieldError> {
        self.add_feature(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)))
    }
}

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("executor validation failed: {0}")]
    ExecutorValidationFailed(String),
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
