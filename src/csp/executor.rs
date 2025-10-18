use super::CspOptions;
use crate::constants::header_keys::CONTENT_SECURITY_POLICY;
use crate::executor::{CachedHeader, ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;

pub struct Csp {
    state: CspExecutorState,
}

enum CspExecutorState {
    Static(CachedHeader<CspOptions>),
    Runtime(CspRuntimeState),
}

struct CspRuntimeState {
    options: CspOptions,
}

impl Csp {
    pub fn new(options: CspOptions) -> Self {
        let state = if options.runtime_nonce_config().is_some() {
            CspExecutorState::Runtime(CspRuntimeState { options })
        } else {
            let header_value = options.header_value();
            CspExecutorState::Static(CachedHeader::new(options, Cow::Owned(header_value)))
        };

        Self { state }
    }

    fn options_ref(&self) -> &CspOptions {
        match &self.state {
            CspExecutorState::Static(cached) => cached.options(),
            CspExecutorState::Runtime(runtime) => &runtime.options,
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
            CspExecutorState::Static(cached) => {
                headers.insert(CONTENT_SECURITY_POLICY, cached.cloned_header_value());
                Ok(())
            }
            CspExecutorState::Runtime(runtime) => {
                let config = runtime
                    .options
                    .runtime_nonce_config()
                    .expect("runtime nonce configuration missing for dynamic CSP executor");
                let nonce_value = config.issue_runtime_value();
                let header_value = runtime.options.render_with_runtime_nonce(&nonce_value);
                headers.insert(CONTENT_SECURITY_POLICY, Cow::Owned(header_value));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
