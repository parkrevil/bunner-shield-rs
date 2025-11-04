use crate::constants::header_values::{SAMESITE_LAX, SAMESITE_NONE, SAMESITE_STRICT};
use crate::executor::FeatureOptions;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSitePolicy {
    Lax,
    Strict,
    None,
}

impl SameSitePolicy {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            SameSitePolicy::Lax => SAMESITE_LAX,
            SameSitePolicy::Strict => SAMESITE_STRICT,
            SameSitePolicy::None => SAMESITE_NONE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieMeta {
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: SameSitePolicy,
}

impl CookieMeta {
    pub(crate) fn new(secure: bool, http_only: bool, same_site: SameSitePolicy) -> Self {
        Self {
            secure,
            http_only,
            same_site,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    pub(crate) meta: CookieMeta,
    pub(crate) enforce_path: Option<String>,
    pub(crate) enforce_domain: Option<String>,
    pub(crate) enforce_max_age: Option<u64>,
}

impl CookiePolicy {
    pub(crate) fn new(meta: CookieMeta) -> Self {
        Self {
            meta,
            enforce_path: None,
            enforce_domain: None,
            enforce_max_age: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SameSiteOptions {
    pub(crate) default: CookiePolicy,
    pub(crate) overrides: HashMap<String, CookiePolicy>,
}

impl SameSiteOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.default.meta.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.default.meta.http_only = http_only;
        self
    }

    pub fn same_site(mut self, same_site: SameSitePolicy) -> Self {
        self.default.meta.same_site = same_site;
        self
    }

    /// Map a specific cookie name to a SameSite policy, using the current default
    /// security flags (Secure/HttpOnly).
    pub fn map_policy_for_cookie(
        mut self,
        name: impl Into<String>,
        policy: SameSitePolicy,
    ) -> Self {
        let name = name.into();
        let mut meta = self.default.meta.clone();
        meta.same_site = policy;
        self.overrides.insert(name, CookiePolicy::new(meta));
        self
    }

    /// Enforce a Path attribute for all cookies if missing.
    pub fn enforce_path(mut self, path: impl Into<String>) -> Self {
        self.default.enforce_path = Some(path.into());
        self
    }

    /// Enforce a Domain attribute for all cookies if missing.
    pub fn enforce_domain(mut self, domain: impl Into<String>) -> Self {
        self.default.enforce_domain = Some(domain.into());
        self
    }

    /// Enforce a Max-Age attribute for all cookies if missing.
    pub fn enforce_max_age(mut self, seconds: u64) -> Self {
        self.default.enforce_max_age = Some(seconds);
        self
    }

    /// Enforce a Path attribute for a specific cookie, if missing.
    pub fn enforce_path_for_cookie(
        mut self,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let entry = self
            .overrides
            .entry(name)
            .or_insert_with(|| CookiePolicy::new(self.default.meta.clone()));
        entry.enforce_path = Some(path.into());
        self
    }

    /// Enforce a Domain attribute for a specific cookie, if missing.
    pub fn enforce_domain_for_cookie(
        mut self,
        name: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let entry = self
            .overrides
            .entry(name)
            .or_insert_with(|| CookiePolicy::new(self.default.meta.clone()));
        entry.enforce_domain = Some(domain.into());
        self
    }

    /// Enforce a Max-Age attribute for a specific cookie, if missing.
    pub fn enforce_max_age_for_cookie(mut self, name: impl Into<String>, seconds: u64) -> Self {
        let name = name.into();
        let entry = self
            .overrides
            .entry(name)
            .or_insert_with(|| CookiePolicy::new(self.default.meta.clone()));
        entry.enforce_max_age = Some(seconds);
        self
    }
}

impl Default for SameSiteOptions {
    fn default() -> Self {
        Self {
            default: CookiePolicy::new(CookieMeta::new(true, true, SameSitePolicy::Lax)),
            overrides: HashMap::new(),
        }
    }
}

impl FeatureOptions for SameSiteOptions {
    type Error = SameSiteOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if matches!(self.default.meta.same_site, SameSitePolicy::None) && !self.default.meta.secure
        {
            return Err(SameSiteOptionsError::SameSiteNoneRequiresSecure);
        }

        for policy in self.overrides.values() {
            if matches!(policy.meta.same_site, SameSitePolicy::None) && !policy.meta.secure {
                return Err(SameSiteOptionsError::SameSiteNoneRequiresSecure);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SameSiteOptionsError {
    #[error("`SameSite=None` requires `Secure` cookies")]
    SameSiteNoneRequiresSecure,
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
