use crate::coep::{Coep, CoepOptions};
use crate::constants::executor_order::{
    CONTENT_SECURITY_POLICY, CROSS_ORIGIN_EMBEDDER_POLICY, CROSS_ORIGIN_OPENER_POLICY, CSRF_TOKEN,
    SAME_SITE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_POWERED_BY,
};
use crate::coop::{Coop, CoopOptions};
use crate::csp::{Csp, CspOptions};
use crate::csrf::{Csrf, CsrfOptions};
use crate::executor::{Executor, ExecutorError};
use crate::hsts::{Hsts, HstsOptions};
use crate::normalized_headers::NormalizedHeaders;
use crate::same_site::{SameSite, SameSiteOptions};
use crate::x_content_type_options::XContentTypeOptions;
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

    pub fn csp(mut self, options: CspOptions) -> Result<Self, ShieldError> {
        self.add_feature(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)))?;

        Ok(self)
    }

    pub fn coop(mut self, options: CoopOptions) -> Result<Self, ShieldError> {
        self.add_feature(CROSS_ORIGIN_OPENER_POLICY, Box::new(Coop::new(options)))?;

        Ok(self)
    }

    pub fn hsts(mut self, options: HstsOptions) -> Result<Self, ShieldError> {
        self.add_feature(STRICT_TRANSPORT_SECURITY, Box::new(Hsts::new(options)))?;

        Ok(self)
    }

    pub fn csrf(mut self, options: CsrfOptions) -> Result<Self, ShieldError> {
        self.add_feature(CSRF_TOKEN, Box::new(Csrf::new(options)))?;

        Ok(self)
    }

    pub fn x_content_type_options(mut self) -> Result<Self, ShieldError> {
        self.add_feature(X_CONTENT_TYPE_OPTIONS, Box::new(XContentTypeOptions::new()))?;

        Ok(self)
    }

    pub fn x_powered_by(mut self) -> Result<Self, ShieldError> {
        self.add_feature(X_POWERED_BY, Box::new(XPoweredBy::new()))?;

        Ok(self)
    }

    pub fn same_site(mut self, options: SameSiteOptions) -> Result<Self, ShieldError> {
        self.add_feature(SAME_SITE, Box::new(SameSite::new(options)))?;

        Ok(self)
    }

    pub fn coep(mut self, options: CoepOptions) -> Result<Self, ShieldError> {
        self.add_feature(CROSS_ORIGIN_EMBEDDER_POLICY, Box::new(Coep::new(options)))?;

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
