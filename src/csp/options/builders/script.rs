use super::super::utils::sanitize_token_input;
use crate::csp::options::{
    CspDirective, CspHashAlgorithm, CspNonce, CspNonceManager, CspOptions, CspSource,
};

pub struct ScriptSrcBuilder<'a> {
    options: &'a mut CspOptions,
}

impl<'a> ScriptSrcBuilder<'a> {
    pub(crate) fn new(options: &'a mut CspOptions) -> Self {
        Self { options }
    }

    pub fn sources<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::ScriptSrc, sources);
        self
    }

    pub fn elem<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::ScriptSrcElem, sources);
        self
    }

    pub fn attr<I, S>(self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.options
            .set_directive_sources(CspDirective::ScriptSrcAttr, sources);
        self
    }

    pub fn nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options.add_script_src_token(&token);
        self
    }

    pub fn nonce_value(self, nonce: CspNonce) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into_inner()));
        self.options.add_script_src_token(&token);
        self
    }

    pub fn hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options.add_script_src_token(&token);
        self
    }

    pub fn elem_nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options
            .add_directive_token(CspDirective::ScriptSrcElem.as_str(), &token);
        self
    }

    pub fn elem_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options
            .add_directive_token(CspDirective::ScriptSrcElem.as_str(), &token);
        self
    }

    pub fn attr_nonce(self, nonce: impl Into<String>) -> Self {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.options
            .add_directive_token(CspDirective::ScriptSrcAttr.as_str(), &token);
        self
    }

    pub fn attr_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.options
            .add_directive_token(CspDirective::ScriptSrcAttr.as_str(), &token);
        self
    }

    pub fn runtime_nonce(self) -> Self {
        self.options.enable_runtime_nonce(CspDirective::ScriptSrc);
        self
    }

    pub fn runtime_nonce_with_manager(self, manager: CspNonceManager) -> Self {
        self.options.set_runtime_nonce_manager(manager);
        self.options.enable_runtime_nonce(CspDirective::ScriptSrc);
        self
    }

    pub fn elem_runtime_nonce(self) -> Self {
        self.options
            .enable_runtime_nonce(CspDirective::ScriptSrcElem);
        self
    }

    pub fn attr_runtime_nonce(self) -> Self {
        self.options
            .enable_runtime_nonce(CspDirective::ScriptSrcAttr);
        self
    }

    pub fn strict_dynamic(self) -> Self {
        self.options.add_script_src_token("'strict-dynamic'");
        self
    }
}
