use super::options::{CookieMeta, SameSiteOptions};
use crate::constants::header_keys::SET_COOKIE;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct SameSite {
    options: SameSiteOptions,
}

impl SameSite {
    pub fn new(options: SameSiteOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for SameSite {
    type Options = SameSiteOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let Some(values) = headers.get_all(SET_COOKIE) else {
            return Ok(());
        };

        let mut cookies: Vec<String> = Vec::with_capacity(values.len());

        for value in values {
            let cookie = value.to_string();
            if cookie.trim().is_empty() {
                continue;
            }
            cookies.push(cookie);
        }

        if cookies.is_empty() {
            return Ok(());
        }

        headers.remove(SET_COOKIE);

        for cookie in cookies {
            let updated = apply_policy(&cookie, &self.options.meta);
            headers.insert_owned(SET_COOKIE, updated);
        }

        Ok(())
    }
}

fn apply_policy(cookie: &str, meta: &CookieMeta) -> String {
    let mut parts = cookie.split(';').map(|part| part.trim().to_string());

    let base = parts.next().unwrap_or_default();
    let mut attributes: Vec<String> = Vec::new();

    for part in parts {
        if part.is_empty() {
            continue;
        }

        let lower = part.to_ascii_lowercase();
        if lower.starts_with("samesite") || lower == "secure" || lower == "httponly" {
            continue;
        }

        attributes.push(part);
    }

    if meta.secure {
        attributes.push("Secure".to_string());
    }

    if meta.http_only {
        attributes.push("HttpOnly".to_string());
    }

    attributes.push(format!("SameSite={}", meta.same_site.as_str()));

    let mut result = base;
    for attr in attributes {
        result.push_str("; ");
        result.push_str(&attr);
    }

    result
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
