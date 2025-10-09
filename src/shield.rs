use crate::constants::executor_order::{
    CONTENT_SECURITY_POLICY, STRICT_TRANSPORT_SECURITY, X_POWERED_BY,
};
use crate::csp::{Csp, CspOptions};
use crate::executor::{Executor, ExecutorError};
use crate::hsts::{Hsts, HstsOptions};
use crate::normalized_headers::NormalizedHeaders;
use crate::x_powered_by::XPoweredBy;
use std::collections::HashMap;
use thiserror::Error;

struct PipelineEntry {
    order: u8,
    executor: Executor,
}

#[derive(Default)]
pub struct Shield {
    pipeline: Vec<PipelineEntry>,
}

impl Shield {
    pub fn new() -> Self {
        Self::default()
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

    pub fn content_security_policy(mut self, options: CspOptions) -> Result<Self, ShieldError> {
        self.add_feature(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)))?;

        Ok(self)
    }

    pub fn strict_transport_security(mut self, options: HstsOptions) -> Result<Self, ShieldError> {
        self.add_feature(STRICT_TRANSPORT_SECURITY, Box::new(Hsts::new(options)))?;

        Ok(self)
    }

    pub fn x_powered_by(mut self) -> Result<Self, ShieldError> {
        self.add_feature(X_POWERED_BY, Box::new(XPoweredBy::new()))?;

        Ok(self)
    }

    fn add_feature(&mut self, order: u8, executor: Executor) -> Result<(), ShieldError> {
        executor
            .validate_options()
            .map_err(ShieldError::ExecutorValidationFailed)?;

        self.pipeline.push(PipelineEntry { order, executor });
        self.pipeline.sort_by(|a, b| a.order.cmp(&b.order));

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("executor validation failed: {0}")]
    ExecutorValidationFailed(ExecutorError),
    #[error("execution failed: {0}")]
    ExecutionFailed(ExecutorError),
}
