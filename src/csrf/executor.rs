use super::options::CsrfOptions;
use super::token::{CsrfTokenError, HmacCsrfService};
use crate::constants::header_keys::{CSRF_TOKEN, SET_COOKIE};
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use thiserror::Error;

const COOKIE_SUFFIX: &str = "; Path=/; Secure; HttpOnly; SameSite=Lax";

pub struct Csrf {
    options: CsrfOptions,
    token_service: HmacCsrfService,
    cookie_prefix: String,
}

impl Csrf {
    pub fn new(options: CsrfOptions) -> Self {
        let secret = options.secret_key;
        let token_service = HmacCsrfService::new(secret);
        let cookie_prefix = format!("{}=", options.cookie_name);

        Self {
            options,
            token_service,
            cookie_prefix,
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

        let mut cookie =
            String::with_capacity(self.cookie_prefix.len() + token.len() + COOKIE_SUFFIX.len());
        cookie.push_str(&self.cookie_prefix);
        cookie.push_str(token.as_str());
        cookie.push_str(COOKIE_SUFFIX);

        headers.insert_owned(CSRF_TOKEN, token);
        headers.insert_owned(SET_COOKIE, cookie);

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CsrfError {
    #[error("failed to generate csrf token: {0}")]
    TokenGeneration(CsrfTokenError),
}
