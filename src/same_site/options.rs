use crate::constants::header_values::{SAMESITE_LAX, SAMESITE_NONE, SAMESITE_STRICT};
use crate::executor::{FeatureOptions, ReportContext};
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
pub struct SameSiteOptions {
    pub(crate) meta: CookieMeta,
}

impl SameSiteOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.meta.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.meta.http_only = http_only;
        self
    }

    pub fn same_site(mut self, same_site: SameSitePolicy) -> Self {
        self.meta.same_site = same_site;
        self
    }
}

impl Default for SameSiteOptions {
    fn default() -> Self {
        Self {
            meta: CookieMeta::new(true, true, SameSitePolicy::Lax),
        }
    }
}

impl FeatureOptions for SameSiteOptions {
    type Error = SameSiteOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if matches!(self.meta.same_site, SameSitePolicy::None) && !self.meta.secure {
            return Err(SameSiteOptionsError::SameSiteNoneRequiresSecure);
        }

        Ok(())
    }

    fn emit_validation_reports(&self, context: &ReportContext) {
        context.push_validation_info(
            "same-site",
            format!(
                "Configured SameSite cookie policy: sameSite={}, secure={}, httpOnly={}",
                self.meta.same_site.as_str(),
                self.meta.secure,
                self.meta.http_only
            ),
        );
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SameSiteOptionsError {
    #[error("SameSite=None requires Secure cookies")]
    SameSiteNoneRequiresSecure,
}
