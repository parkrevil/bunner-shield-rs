use super::super::utils::sanitize_token_input;
use crate::csp::options::{CspDirective, CspHashAlgorithm, CspNonceManager, CspOptions, CspSource};

pub struct StyleSrcBuilder<'a> {
    options: &'a mut CspOptions,
}

impl<'a> StyleSrcBuilder<'a> {
    pub(crate) fn new(options: &'a mut CspOptions) -> Self {
        Self { options }
    }

    pub fn sources<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::StyleSrc, sources);
        self
    }

    pub fn elem<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::StyleSrcElem, sources);
        self
    }

    pub fn attr<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::StyleSrcAttr, sources);
        self
    }

    pub fn nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options
            .add_directive_token(CspDirective::StyleSrc.as_str(), &token);
        self
    }

    pub fn hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options
            .add_directive_token(CspDirective::StyleSrc.as_str(), &token);
        self
    }

    pub fn elem_nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options
            .add_directive_token(CspDirective::StyleSrcElem.as_str(), &token);
        self
    }

    pub fn elem_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options
            .add_directive_token(CspDirective::StyleSrcElem.as_str(), &token);
        self
    }

    pub fn attr_nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options
            .add_directive_token(CspDirective::StyleSrcAttr.as_str(), &token);
        self
    }

    pub fn attr_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options
            .add_directive_token(CspDirective::StyleSrcAttr.as_str(), &token);
        self
    }

    pub fn runtime_nonce(self) -> Self {
        self.options.enable_runtime_nonce(CspDirective::StyleSrc);
        self
    }

    pub fn runtime_nonce_with_manager(self, manager: CspNonceManager) -> Self {
        self.options.set_runtime_nonce_manager(manager);
        self.options.enable_runtime_nonce(CspDirective::StyleSrc);
        self
    }

    pub fn elem_runtime_nonce(self) -> Self {
        self.options
            .enable_runtime_nonce(CspDirective::StyleSrcElem);
        self
    }

    pub fn attr_runtime_nonce(self) -> Self {
        self.options
            .enable_runtime_nonce(CspDirective::StyleSrcAttr);
        self
    }
}

#[cfg(test)]
#[path = "style_test.rs"]
mod style_test;
