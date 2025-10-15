use super::options::{CookieMeta, SameSiteOptions};
use crate::constants::header_keys::SET_COOKIE;
use crate::executor::{ExecutorError, FeatureExecutor, ReportContext};
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
        let Some(existing) = headers.get(SET_COOKIE) else {
            return Ok(());
        };

        let updated = apply_policy(existing, &self.options.meta);
        headers.insert(SET_COOKIE, updated);

        Ok(())
    }

    fn emit_runtime_report(
        &self,
        context: &ReportContext,
        headers: &NormalizedHeaders,
    ) -> Result<(), ExecutorError> {
        if headers.get(SET_COOKIE).is_some() {
            context.push_runtime_info(
                "same-site",
                format!(
                    "Applied SameSite policy {} with Secure={} and HttpOnly={}",
                    self.options.meta.same_site.as_str(),
                    self.options.meta.secure,
                    self.options.meta.http_only
                ),
            );
        }

        Ok(())
    }
}

fn apply_policy(cookie: &str, meta: &CookieMeta) -> String {
    let parts: Vec<String> = cookie
        .split(';')
        .map(|part| part.trim().to_string())
        .collect();

    if parts.is_empty() {
        return cookie.to_string();
    }

    let mut attributes: Vec<String> = Vec::new();
    let mut base = String::new();

    for (index, part) in parts.into_iter().enumerate() {
        if index == 0 {
            base = part;
            continue;
        }

        let lower = part.to_ascii_lowercase();
        if lower.starts_with("samesite") || lower == "secure" || lower == "httponly" {
            continue;
        }

        if !part.is_empty() {
            attributes.push(part);
        }
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
