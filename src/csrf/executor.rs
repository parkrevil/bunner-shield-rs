use super::options::CsrfOptions;
use super::token::{CsrfTokenError, HmacCsrfService};
use crate::constants::header_keys::{CSRF_TOKEN, SET_COOKIE};
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use thiserror::Error;

pub struct Csrf {
    options: CsrfOptions,
    token_service: HmacCsrfService,
}

impl Csrf {
    pub fn new(options: CsrfOptions) -> Self {
        let secret = options.secret_key;
        let token_service = HmacCsrfService::new(secret);

        Self {
            options,
            token_service,
        }
    }
}

impl FeatureExecutor for Csrf {
    type Options = CsrfOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let token = self
            .token_service
            .issue(self.options.token_length)
            .map_err(|err| Box::new(CsrfError::TokenGeneration(err)) as ExecutorError)?;

        headers.insert(CSRF_TOKEN, token.as_str());
        headers.insert(
            SET_COOKIE,
            format!(
                "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                &self.options.cookie_name, &token
            ),
        );

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CsrfError {
    #[error("failed to generate csrf token: {0}")]
    TokenGeneration(CsrfTokenError),
}
