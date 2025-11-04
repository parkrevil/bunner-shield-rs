use crate::clear_site_data::{ClearSiteData, ClearSiteDataOptions};
use crate::coep::{Coep, CoepOptions};
use crate::constants::executor_order::{
    CLEAR_SITE_DATA, CONTENT_SECURITY_POLICY, CROSS_ORIGIN_EMBEDDER_POLICY,
    CROSS_ORIGIN_OPENER_POLICY, CROSS_ORIGIN_RESOURCE_POLICY, CSRF_TOKEN, FETCH_METADATA,
    ORIGIN_AGENT_CLUSTER, PERMISSIONS_POLICY, REFERRER_POLICY, SAFE_HEADERS, SAME_SITE,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_DNS_PREFETCH_CONTROL, X_FRAME_OPTIONS,
    X_POWERED_BY,
};
use crate::coop::{Coop, CoopOptions};
use crate::corp::{Corp, CorpOptions};
use crate::csp::{Csp, CspOptions};
use crate::csrf::{Csrf, CsrfOptions};
use crate::executor::{Executor, ExecutorError};
use crate::fetch_metadata::{FetchMetadata, FetchMetadataOptions};
use crate::hsts::{Hsts, HstsOptions};
use crate::normalized_headers::{NormalizedHeaders, NormalizedResult};
use crate::origin_agent_cluster::{OriginAgentCluster, OriginAgentClusterOptions};
use crate::permissions_policy::{PermissionsPolicy, PermissionsPolicyOptions};
use crate::referrer_policy::{ReferrerPolicy as ReferrerPolicyExecutor, ReferrerPolicyOptions};
use crate::safe_headers::SafeHeaders;
use crate::same_site::{SameSite, SameSiteOptions};
use crate::x_content_type_options::XContentTypeOptions;
use crate::x_dns_prefetch_control::{XdnsPrefetchControl, XdnsPrefetchControlOptions};
use crate::x_frame_options::{XFrameOptions, XFrameOptionsOptions};
use crate::x_powered_by::XPoweredBy;
use std::collections::HashMap;
use thiserror::Error;

struct PipelineEntry {
    order: u8,
    executor: Executor,
}

pub struct Shield {
    pipeline: Vec<PipelineEntry>,
}

impl Default for Shield {
    fn default() -> Self {
        let pipeline = vec![PipelineEntry {
            order: SAFE_HEADERS,
            executor: Box::new(SafeHeaders::new()),
        }];

        Self { pipeline }
    }
}

impl Shield {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a builder that collects features without validating them immediately.
    /// Validation is performed at `secure()` time.
    pub fn builder() -> ShieldBuilder {
        ShieldBuilder::default()
    }

    pub fn secure(
        &self,
        headers: HashMap<String, String>,
    ) -> Result<HashMap<String, String>, ShieldError> {
        let mut normalized = NormalizedHeaders::new(headers);

        // Validate all executors before execution (builder path defers validation until now).
        for entry in &self.pipeline {
            entry
                .executor
                .validate_options()
                .map_err(ShieldError::ExecutorValidationFailed)?;
        }

        for entry in &self.pipeline {
            entry
                .executor
                .execute(&mut normalized)
                .map_err(ShieldError::ExecutionFailed)?;
        }

        Ok(normalized.into_result())
    }

    /// Like `secure`, but preserves multi-value headers (e.g., Set-Cookie) distinctly.
    pub fn secure_with_multi(
        &self,
        headers: HashMap<String, String>,
    ) -> Result<NormalizedResult, ShieldError> {
        let mut normalized = NormalizedHeaders::new(headers);

        // Validate all executors before execution (builder path defers validation until now).
        for entry in &self.pipeline {
            entry
                .executor
                .validate_options()
                .map_err(ShieldError::ExecutorValidationFailed)?;
        }

        for entry in &self.pipeline {
            entry
                .executor
                .execute(&mut normalized)
                .map_err(ShieldError::ExecutionFailed)?;
        }

        Ok(normalized.into_result_with_multi())
    }

    pub fn csp(mut self, options: CspOptions) -> Result<Self, ShieldError> {
        self.add_feature(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)))
            .map(|_| self)
    }

    pub fn fetch_metadata(mut self, options: FetchMetadataOptions) -> Result<Self, ShieldError> {
        self.add_feature(FETCH_METADATA, Box::new(FetchMetadata::new(options)))
            .map(|_| self)
    }

    pub fn coop(mut self, options: CoopOptions) -> Result<Self, ShieldError> {
        self.add_feature(CROSS_ORIGIN_OPENER_POLICY, Box::new(Coop::new(options)))
            .map(|_| self)
    }

    pub fn corp(mut self, options: CorpOptions) -> Result<Self, ShieldError> {
        self.add_feature(CROSS_ORIGIN_RESOURCE_POLICY, Box::new(Corp::new(options)))
            .map(|_| self)
    }

    pub fn hsts(mut self, options: HstsOptions) -> Result<Self, ShieldError> {
        self.add_feature(STRICT_TRANSPORT_SECURITY, Box::new(Hsts::new(options)))
            .map(|_| self)
    }

    pub fn csrf(mut self, options: CsrfOptions) -> Result<Self, ShieldError> {
        self.add_feature(CSRF_TOKEN, Box::new(Csrf::new(options)))
            .map(|_| self)
    }

    pub fn x_content_type_options(mut self) -> Result<Self, ShieldError> {
        self.add_feature(X_CONTENT_TYPE_OPTIONS, Box::new(XContentTypeOptions::new()))
            .map(|_| self)
    }

    pub fn permissions_policy(
        mut self,
        options: PermissionsPolicyOptions,
    ) -> Result<Self, ShieldError> {
        self.add_feature(
            PERMISSIONS_POLICY,
            Box::new(PermissionsPolicy::new(options)),
        )
        .map(|_| self)
    }

    pub fn x_dns_prefetch_control(
        mut self,
        options: XdnsPrefetchControlOptions,
    ) -> Result<Self, ShieldError> {
        self.add_feature(
            X_DNS_PREFETCH_CONTROL,
            Box::new(XdnsPrefetchControl::new(options)),
        )
        .map(|_| self)
    }

    pub fn clear_site_data(mut self, options: ClearSiteDataOptions) -> Result<Self, ShieldError> {
        self.add_feature(CLEAR_SITE_DATA, Box::new(ClearSiteData::new(options)))
            .map(|_| self)
    }

    pub fn x_frame_options(mut self, options: XFrameOptionsOptions) -> Result<Self, ShieldError> {
        self.add_feature(X_FRAME_OPTIONS, Box::new(XFrameOptions::new(options)))
            .map(|_| self)
    }

    pub fn x_powered_by(mut self) -> Result<Self, ShieldError> {
        self.add_feature(X_POWERED_BY, Box::new(XPoweredBy::new()))
            .map(|_| self)
    }

    pub fn referrer_policy(mut self, options: ReferrerPolicyOptions) -> Result<Self, ShieldError> {
        self.add_feature(
            REFERRER_POLICY,
            Box::new(ReferrerPolicyExecutor::new(options)),
        )
        .map(|_| self)
    }

    pub fn origin_agent_cluster(
        mut self,
        options: OriginAgentClusterOptions,
    ) -> Result<Self, ShieldError> {
        self.add_feature(
            ORIGIN_AGENT_CLUSTER,
            Box::new(OriginAgentCluster::new(options)),
        )
        .map(|_| self)
    }

    pub fn same_site(mut self, options: SameSiteOptions) -> Result<Self, ShieldError> {
        self.add_feature(SAME_SITE, Box::new(SameSite::new(options)))
            .map(|_| self)
    }

    pub fn coep(mut self, options: CoepOptions) -> Result<Self, ShieldError> {
        self.add_feature(CROSS_ORIGIN_EMBEDDER_POLICY, Box::new(Coep::new(options)))
            .map(|_| self)
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

/// Fluent builder for `Shield` that defers option validation until `secure()` is called.
pub struct ShieldBuilder {
    pipeline: Vec<PipelineEntry>,
}

impl Default for ShieldBuilder {
    fn default() -> Self {
        let pipeline = vec![PipelineEntry {
            order: SAFE_HEADERS,
            executor: Box::new(SafeHeaders::new()),
        }];
        Self { pipeline }
    }
}

impl ShieldBuilder {
    fn push(&mut self, order: u8, executor: Executor) {
        self.pipeline.push(PipelineEntry { order, executor });
        self.pipeline.sort_by(|a, b| a.order.cmp(&b.order));
    }

    pub fn csp(mut self, options: CspOptions) -> Self {
        self.push(CONTENT_SECURITY_POLICY, Box::new(Csp::new(options)));
        self
    }

    pub fn fetch_metadata(mut self, options: FetchMetadataOptions) -> Self {
        self.push(FETCH_METADATA, Box::new(FetchMetadata::new(options)));
        self
    }

    pub fn coop(mut self, options: CoopOptions) -> Self {
        self.push(CROSS_ORIGIN_OPENER_POLICY, Box::new(Coop::new(options)));
        self
    }

    pub fn corp(mut self, options: CorpOptions) -> Self {
        self.push(CROSS_ORIGIN_RESOURCE_POLICY, Box::new(Corp::new(options)));
        self
    }

    pub fn hsts(mut self, options: HstsOptions) -> Self {
        self.push(STRICT_TRANSPORT_SECURITY, Box::new(Hsts::new(options)));
        self
    }

    pub fn csrf(mut self, options: CsrfOptions) -> Self {
        self.push(CSRF_TOKEN, Box::new(Csrf::new(options)));
        self
    }

    pub fn x_content_type_options(mut self) -> Self {
        self.push(X_CONTENT_TYPE_OPTIONS, Box::new(XContentTypeOptions::new()));
        self
    }

    pub fn permissions_policy(mut self, options: PermissionsPolicyOptions) -> Self {
        self.push(
            PERMISSIONS_POLICY,
            Box::new(PermissionsPolicy::new(options)),
        );
        self
    }

    pub fn x_dns_prefetch_control(mut self, options: XdnsPrefetchControlOptions) -> Self {
        self.push(
            X_DNS_PREFETCH_CONTROL,
            Box::new(XdnsPrefetchControl::new(options)),
        );
        self
    }

    pub fn clear_site_data(mut self, options: ClearSiteDataOptions) -> Self {
        self.push(CLEAR_SITE_DATA, Box::new(ClearSiteData::new(options)));
        self
    }

    pub fn x_frame_options(mut self, options: XFrameOptionsOptions) -> Self {
        self.push(X_FRAME_OPTIONS, Box::new(XFrameOptions::new(options)));
        self
    }

    pub fn x_powered_by(mut self) -> Self {
        self.push(X_POWERED_BY, Box::new(XPoweredBy::new()));
        self
    }

    pub fn referrer_policy(mut self, options: ReferrerPolicyOptions) -> Self {
        self.push(
            REFERRER_POLICY,
            Box::new(ReferrerPolicyExecutor::new(options)),
        );
        self
    }

    pub fn origin_agent_cluster(mut self, options: OriginAgentClusterOptions) -> Self {
        self.push(
            ORIGIN_AGENT_CLUSTER,
            Box::new(OriginAgentCluster::new(options)),
        );
        self
    }

    pub fn same_site(mut self, options: SameSiteOptions) -> Self {
        self.push(SAME_SITE, Box::new(SameSite::new(options)));
        self
    }

    pub fn coep(mut self, options: CoepOptions) -> Self {
        self.push(CROSS_ORIGIN_EMBEDDER_POLICY, Box::new(Coep::new(options)));
        self
    }

    /// Finalizes the builder and returns a Shield instance. Options are validated on `secure()`.
    pub fn build(self) -> Shield {
        Shield {
            pipeline: self.pipeline,
        }
    }
}

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("executor validation failed: {0}")]
    ExecutorValidationFailed(ExecutorError),
    #[error("execution failed: {0}")]
    ExecutionFailed(ExecutorError),
}

/// High-level categories for `ShieldError` to enable quick classification
/// while preserving the original error via `source()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldErrorKind {
    Validation,
    Execution,
}

impl ShieldError {
    /// Returns the error category without allocating or inspecting inner text.
    pub fn kind(&self) -> ShieldErrorKind {
        match self {
            ShieldError::ExecutorValidationFailed(_) => ShieldErrorKind::Validation,
            ShieldError::ExecutionFailed(_) => ShieldErrorKind::Execution,
        }
    }

    /// Convenience: true if this is a validation error produced before execution.
    pub fn is_validation(&self) -> bool {
        matches!(self, ShieldError::ExecutorValidationFailed(_))
    }

    /// Convenience: true if this is an execution error produced while applying headers.
    pub fn is_execution(&self) -> bool {
        matches!(self, ShieldError::ExecutionFailed(_))
    }
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
