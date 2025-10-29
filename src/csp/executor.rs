use super::CspOptions;
use crate::constants::header_keys::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY};
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor, PolicyMode};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;
use thiserror::Error;

pub struct Csp {
    state: CspExecutorState,
}

enum CspExecutorState {
    Static {
        cached: CachedHeader<CspOptions>,
        header_key: &'static str,
    },
    Runtime {
        options: CspOptions,
        header_key: &'static str,
    },
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        let header_key = header_key_for_mode(options.mode());
        let state = if options.runtime_nonce_config().is_some() {
            CspExecutorState::Runtime {
                options,
                header_key,
            }
        } else {
            let header_value = options.header_value();
            CspExecutorState::Static {
                cached: CachedHeader::new(options, Cow::Owned(header_value)),
                header_key,
            }
        };

        Self { state }
    }

    fn options_ref(&self) -> &CspOptions {
        match &self.state {
            CspExecutorState::Static { cached, .. } => cached.options(),
            CspExecutorState::Runtime { options, .. } => options,
        }
    }
}

impl FeatureExecutor for Csp {
    type Options = CspOptions;

    fn options(&self) -> &Self::Options {
        self.options_ref()
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        match &self.state {
            CspExecutorState::Static { cached, header_key } => {
                headers.insert(*header_key, cached.cloned_header_value());
                Ok(())
            }
            CspExecutorState::Runtime {
                options,
                header_key,
            } => {
                let Some(config) = options.runtime_nonce_config() else {
                    return Err(Box::new(CspError::MissingRuntimeNonceConfig) as ExecutorError);
                };
                let nonce_value = config.issue_runtime_value();
                let header_value = options.render_with_runtime_nonce(&nonce_value);
                headers.insert(*header_key, Cow::Owned(header_value));
                Ok(())
            }
        }
    }
}

fn header_key_for_mode(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Enforce => CONTENT_SECURITY_POLICY,
        PolicyMode::ReportOnly => CONTENT_SECURITY_POLICY_REPORT_ONLY,
    }
}

#[derive(Debug, Error)]
pub enum CspError {
    #[error("runtime nonce configuration missing for dynamic CSP executor")]
    MissingRuntimeNonceConfig,
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
