use crate::constants::executor_order::CONTENT_SECURITY_POLICY;
use crate::csp::{Csp, CspOptions};
use crate::executor::ShieldExecutor;
use crate::normalized_headers::NormalizedHeaders;
use std::collections::HashMap;
use thiserror::Error;

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

    fn add_feature(mut self, order: u8, executor: ShieldExecutor) -> Result<Self, ShieldError> {
        executor
            .validate_options()
            .map_err(ShieldError::ExecutorValidationFailed)?;

        self.pipeline.push(PipelineEntry { order, executor });
        self.pipeline.sort_by(|a, b| a.order.cmp(&b.order));

        Ok(self)
    }

    pub fn secure(
        &self,
        headers: HashMap<String, String>,
    ) -> Result<HashMap<String, String>, ShieldError> {
        let mut normalized = NormalizedHeaders::new(headers);

        for entry in &self.pipeline {
            entry
                .executor
                .execute(&mut normalized)
                .map_err(ShieldError::ExecutionFailed)?;
        }

        Ok(normalized.into_result())
    }

    pub fn content_security_policy(self, options: CspOptions) -> Result<Self, ShieldError> {
        self.add_feature(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)))
    }
}

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("executor validation failed: {0}")]
    ExecutorValidationFailed(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
}
