use super::options::{CookieMeta, CookiePolicy, SameSiteOptions};
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
            let updated = apply_policy_with_options(&cookie, &self.options);
            headers.insert_owned(SET_COOKIE, updated);
        }

        Ok(())
    }
}

fn apply_policy_inner(cookie: &str, policy: &CookiePolicy) -> String {
    let mut parts = cookie.split(';').map(|part| part.trim().to_string());

    let base = parts.next().unwrap_or_default();
    let meta: &CookieMeta = &policy.meta;

    let mut attributes: Vec<String> = Vec::new();
    let mut has_path = false;
    let mut has_domain = false;
    let mut has_max_age = false;

    for part in parts {
        if part.is_empty() {
            continue;
        }

        let lower = part.to_ascii_lowercase();
        if lower.starts_with("samesite") || lower == "secure" || lower == "httponly" {
            // Strip security attributes; they'll be re-applied from policy
            continue;
        }

        if lower.starts_with("path=") {
            has_path = true;
        } else if lower.starts_with("domain=") {
            has_domain = true;
        } else if lower.starts_with("max-age=") {
            has_max_age = true;
        }

        // Preserve other attributes
        attributes.push(part);
    }

    if meta.secure {
        attributes.push("Secure".to_string());
    }

    if meta.http_only {
        attributes.push("HttpOnly".to_string());
    }

    attributes.push(format!("SameSite={}", meta.same_site.as_str()));

    // Enforce additional attributes if configured and missing
    if let Some(path) = &policy.enforce_path
        && !has_path
    {
        attributes.push(format!("Path={}", path));
    }
    if let Some(domain) = &policy.enforce_domain
        && !has_domain
    {
        attributes.push(format!("Domain={}", domain));
    }
    if let Some(seconds) = policy.enforce_max_age
        && !has_max_age
    {
        attributes.push(format!("Max-Age={}", seconds));
    }

    let mut result = base;
    for attr in attributes {
        result.push_str("; ");
        result.push_str(&attr);
    }

    result
}

// Backward-compatible helper for tests that validate security attribute rewriting
#[cfg(test)]
fn apply_policy(cookie: &str, meta: &CookieMeta) -> String {
    let policy = CookiePolicy::new(meta.clone());
    apply_policy_inner(cookie, &policy)
}

fn apply_policy_with_options(cookie: &str, options: &SameSiteOptions) -> String {
    let base = cookie
        .split(';')
        .next()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let cookie_name = base.split('=').next().unwrap_or("").trim();
    let policy: &CookiePolicy = options
        .overrides
        .get(cookie_name)
        .unwrap_or(&options.default);
    apply_policy_inner(cookie, policy)
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
