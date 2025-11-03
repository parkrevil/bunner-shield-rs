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

    /// Verifies the incoming request for CSRF concerns.
    /// - For state-changing methods (POST/PUT/PATCH/DELETE by default), requires a valid X-CSRF-Token within max-age.
    /// - If origin validation is enabled, validates Origin/Referer against the Host header.
    pub fn verify_request(&self, headers: &NormalizedHeaders) -> Result<(), ExecutorError> {
        if let Some(method) = request_method(headers)
            && should_verify(&self.options.validate_methods, &method)
        {
            let token = headers
                .get_all(CSRF_TOKEN)
                .and_then(|vals| vals.first())
                .map(|v| v.as_ref().to_string());
            match token {
                Some(t) if !t.is_empty() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| Box::new(CsrfError::SystemTime) as ExecutorError)?
                        .as_secs();
                    if let Err(err) = self.token_service.verify_with_max_age(
                        &t,
                        self.options.token_max_age_secs,
                        now,
                    ) {
                        return Err(Box::new(CsrfError::VerificationFailed(err)) as ExecutorError);
                    }
                }
                _ => {
                    return Err(Box::new(CsrfError::MissingToken) as ExecutorError);
                }
            }
        }

        if self.options.origin_validation {
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

            let allowed: Vec<&str> = self
                .options
                .allowed_origins
                .iter()
                .map(|s| s.as_str())
                .collect();

            if let Err(err) = validate_origin(&req_headers, self.options.use_referer, &allowed) {
                return Err(Box::new(CsrfError::OriginValidation(err)) as ExecutorError);
            }
        }

        Ok(())
    }

    /// Issues a fresh CSRF token and corresponding Set-Cookie header on the response.
    pub fn issue_response(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
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

impl FeatureExecutor for Csrf {
    type Options = CsrfOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        self.verify_request(headers)?;
        self.issue_response(headers)
    }
}

#[derive(Debug, Error)]
pub enum CsrfError {
    #[error("failed to generate CSRF token: {0}")]
    TokenGeneration(CsrfTokenError),
    #[error("origin/referer validation failed: {0}")]
    OriginValidation(super::origin::OriginCheckError),
    #[error("missing X-CSRF-Token header for state-changing request")]
    MissingToken,
    #[error("system clock error while verifying CSRF token")]
    SystemTime,
    #[error("CSRF token verification failed: {0}")]
    VerificationFailed(CsrfTokenError),
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;

fn request_method(headers: &NormalizedHeaders) -> Option<String> {
    // Try common header keys that tests/framework adapters can set.
    // X-Request-Method (custom), Method (generic), and pseudo-header ":method" if passed through.
    for name in ["X-Request-Method", "Method", ":method"] {
        if let Some(values) = headers.get_all(name)
            && let Some(v) = values.first()
        {
            return Some(v.as_ref().to_ascii_uppercase());
        }
    }
    None
}

fn should_verify(configured: &[String], method: &str) -> bool {
    configured.iter().any(|m| m.eq_ignore_ascii_case(method))
}
