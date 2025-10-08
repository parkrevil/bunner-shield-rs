use crate::csp::{Csp, CspOptions, CspOptionsError};
use crate::executor::Executor;
use crate::normalized_headers::NormalizedHeaders;

type HeaderExecutor = Box<dyn Executor<Output = Vec<(String, String)>> + 'static>;

#[derive(Default)]
pub struct Shield {
    pipeline: Vec<HeaderExecutor>,
}

impl Shield {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn content_security_policy(
        mut self,
        options: CspOptions,
    ) -> Result<Self, CspOptionsError> {
        let validated = options.validate()?;
        let executor: HeaderExecutor = Box::new(Csp::new(validated));
        self.pipeline.push(executor);
        Ok(self)
    }

    pub fn secure(&self, mut headers: Vec<(String, String)>) -> NormalizedHeaders {
        for executor in &self.pipeline {
            headers.extend(executor.execute());
        }

        NormalizedHeaders::from_pairs(headers)
    }
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
