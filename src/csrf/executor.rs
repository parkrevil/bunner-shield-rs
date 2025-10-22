use super::options::CsrfOptions;
use super::origin::validate_origin;
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
        let token_service =
            HmacCsrfService::with_verification_keys(secret, options.verification_keys.clone());
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
        // Optional request-origin check before issuing a token
        if self.options.origin_validation {
            // Build a simple map from current headers for lookup
            let mut req_headers = std::collections::HashMap::new();
            if let Some(values) = headers.get_all("Origin")
                && let Some(v) = values.first()
            {
                req_headers.insert("Origin".to_string(), v.to_string());
            }
            if let Some(values) = headers.get_all("Referer")
                && let Some(v) = values.first()
            {
                req_headers.insert("Referer".to_string(), v.to_string());
            }

            // Derive allowed origin from current host header if present; otherwise skip check.
            // Many frameworks pass Host via headers; if missing, we can't validate.
            if let Some(host_vals) = headers.get_all("Host")
                && let Some(host) = host_vals.first()
            {
                // Assume https by default; production servers should run behind TLS.
                let allowed0 = format!("https://{}", host);
                let allowed_refs = [allowed0.as_str()];
                if let Err(err) =
                    validate_origin(&req_headers, self.options.use_referer, &allowed_refs)
                {
                    return Err(Box::new(CsrfError::OriginValidation(err)) as ExecutorError);
                }
            }
        }

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
    #[error("failed to generate CSRF token: {0}")]
    TokenGeneration(CsrfTokenError),
    #[error("origin/referer validation failed: {0}")]
    OriginValidation(super::origin::OriginCheckError),
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
