use std::collections::HashSet;

use crate::executor::FeatureOptions;

use super::builders::{ScriptSrcBuilder, StyleSrcBuilder, TrustedTypesBuilder};
use super::nonce::{self, CspNonceManager};
use super::runtime_nonce::RuntimeNonceConfig;
use super::sandbox::SandboxToken;
use super::sources::CspSource;
use super::types::CspDirective;
use super::utils::{contains_token, format_sources, sanitize_token_input};
use super::validation;
#[cfg(test)]
use super::validation::TokenValidationCache;

#[derive(Debug, Clone, Default)]
pub struct CspOptions {
    pub(crate) directives: Vec<(String, String)>,
    pub(crate) runtime_nonce: Option<RuntimeNonceConfig>,
}

impl CspOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn runtime_nonce_manager(mut self, manager: CspNonceManager) -> Self {
        self.set_runtime_nonce_manager(manager);
        self
    }

    pub(crate) fn set_runtime_nonce_manager(&mut self, manager: CspNonceManager) {
        match self.runtime_nonce {
            Some(ref mut config) => config.set_manager(manager),
            None => self.runtime_nonce = Some(RuntimeNonceConfig::with_manager(manager)),
        }
    }

    pub fn default_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::DefaultSrc, sources);
        self
    }

    pub fn script_src<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(ScriptSrcBuilder<'_>) -> ScriptSrcBuilder<'_>,
    {
        let builder = ScriptSrcBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub(crate) fn enable_runtime_nonce(&mut self, directive: CspDirective) {
        let directive_name = directive.as_str();
        if self
            .runtime_nonce
            .as_ref()
            .map(|config| config.has_directive(directive_name))
            .unwrap_or(false)
        {
            return;
        }

        let placeholder = {
            let config = self
                .runtime_nonce
                .get_or_insert_with(RuntimeNonceConfig::new);
            config.allocate_placeholder()
        };

        self.add_directive_token(directive_name, &placeholder);

        if let Some(config) = self.runtime_nonce.as_mut() {
            config.record_directive(directive_name, placeholder);
        }
    }

    pub fn style_src<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(StyleSrcBuilder<'_>) -> StyleSrcBuilder<'_>,
    {
        let builder = StyleSrcBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub fn img_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ImgSrc, sources);
        self
    }

    pub fn connect_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ConnectSrc, sources);
        self
    }

    pub fn font_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FontSrc, sources);
        self
    }

    pub fn frame_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FrameSrc, sources);
        self
    }

    pub fn worker_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::WorkerSrc, sources);
        self
    }

    pub fn navigate_to<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::NavigateTo, sources);
        self
    }

    pub fn object_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ObjectSrc, sources);
        self
    }

    pub fn media_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::MediaSrc, sources);
        self
    }

    pub fn manifest_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ManifestSrc, sources);
        self
    }

    pub fn frame_ancestors<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FrameAncestors, sources);
        self
    }

    pub fn base_uri<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::BaseUri, sources);
        self
    }

    pub fn form_action<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FormAction, sources);
        self
    }

    pub fn trusted_types<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(TrustedTypesBuilder<'_>) -> TrustedTypesBuilder<'_>,
    {
        let builder = TrustedTypesBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.set_flag_directive(CspDirective::UpgradeInsecureRequests);
        self
    }

    pub fn block_all_mixed_content(mut self) -> Self {
        self.set_flag_directive(CspDirective::BlockAllMixedContent);
        self
    }

    pub fn sandbox(mut self) -> Self {
        self.set_flag_directive(CspDirective::Sandbox);
        self
    }

    pub fn sandbox_with<I>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = SandboxToken>,
    {
        let mut rendered = Vec::new();
        let mut seen = HashSet::new();

        for token in tokens.into_iter() {
            let value = token.as_str();
            if seen.insert(value) {
                rendered.push(value);
            }
        }

        let value = rendered.join(" ");
        self.set_directive(CspDirective::Sandbox.as_str(), &value);
        self
    }

    pub fn report_to(mut self, group: impl Into<String>) -> Self {
        let value = group.into().trim().to_string();
        self.set_directive(CspDirective::ReportTo.as_str(), &value);
        self
    }

    pub fn add_source<S>(mut self, directive: CspDirective, source: S) -> Self
    where
        S: Into<CspSource>,
    {
        let token_string = source.into().to_string();
        let trimmed = token_string.trim();

        if trimmed.is_empty() {
            return self;
        }

        self.add_directive_token(directive.as_str(), trimmed);
        self
    }

    pub fn merge(mut self, other: &CspOptions) -> Self {
        for (name, value) in &other.directives {
            if name == CspDirective::ReportTo.as_str() {
                if self.directives.iter().all(|(existing, _)| existing != name) {
                    self.set_directive(name, value);
                }
                continue;
            }

            let trimmed = value.trim();
            if trimmed.is_empty() {
                if self.directives.iter().all(|(existing, _)| existing != name) {
                    self.set_directive(name, value);
                }
                continue;
            }

            for token in trimmed.split_whitespace() {
                self.add_directive_token(name, token);
            }
        }

        self.merge_runtime_nonce(other);

        self
    }

    fn merge_runtime_nonce(&mut self, other: &CspOptions) {
        if let Some(other_config) = other.runtime_nonce.as_ref() {
            match self.runtime_nonce.as_mut() {
                Some(config) => {
                    if config.is_empty() {
                        config.adopt_strategy(other_config);
                    }
                    config.merge(other_config);
                }
                None => {
                    self.runtime_nonce = Some(other_config.clone());
                }
            }
        }
    }

    pub(crate) fn set_directive_sources<I, S>(&mut self, directive: CspDirective, sources: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        let value = format_sources(sources);
        self.set_directive(directive.as_str(), &value);
    }

    fn set_flag_directive(&mut self, directive: CspDirective) {
        self.set_directive(directive.as_str(), "");
    }

    pub fn require_trusted_types_for_scripts(mut self) -> Self {
        self.set_directive(CspDirective::RequireTrustedTypesFor.as_str(), "'script'");
        self
    }

    pub fn generate_nonce() -> String {
        nonce::generate_nonce()
    }

    pub fn generate_nonce_with_size(byte_len: usize) -> String {
        nonce::generate_nonce_with_size(byte_len)
    }

    pub(crate) fn is_valid_directive_name(name: &str) -> bool {
        CspDirective::ALL
            .iter()
            .any(|directive| directive.as_str() == name)
    }

    pub fn header_value(&self) -> String {
        self.directives
            .iter()
            .map(|(name, value)| {
                if value.is_empty() {
                    name.clone()
                } else {
                    format!("{} {}", name, value)
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub(crate) fn runtime_nonce_config(&self) -> Option<&RuntimeNonceConfig> {
        self.runtime_nonce.as_ref()
    }

    pub(crate) fn render_with_runtime_nonce(&self, nonce_value: &str) -> String {
        let Some(config) = self.runtime_nonce.as_ref() else {
            return self.header_value();
        };

        let sanitized = sanitize_token_input(nonce_value.to_string());
        let replacement = format!("'nonce-{}'", sanitized);
        let mappings: Vec<(String, String)> = config
            .directives()
            .map(|(name, placeholder)| (name.clone(), placeholder.clone()))
            .collect();
        let mut clone = self.clone();

        for (directive, placeholder) in &mappings {
            clone.replace_nonce_token(directive, placeholder, &replacement);
        }

        clone.header_value()
    }

    fn replace_nonce_token(&mut self, directive: &str, placeholder: &str, replacement: &str) {
        if let Some((_, value)) = self
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
        {
            if value.trim().is_empty() {
                *value = replacement.to_string();
                return;
            }

            let mut tokens: Vec<String> = value
                .split_whitespace()
                .map(|token| {
                    if token == placeholder {
                        replacement.to_string()
                    } else {
                        token.to_string()
                    }
                })
                .collect();

            if !tokens.iter().any(|token| token == replacement) {
                tokens.push(replacement.to_string());
            }

            *value = tokens.join(" ");
        } else {
            self.directives
                .push((directive.to_string(), replacement.to_string()));
        }
    }

    pub(crate) fn add_script_src_token(&mut self, token: &str) {
        self.add_directive_token(CspDirective::ScriptSrc.as_str(), token);
    }

    pub(crate) fn add_directive_token(&mut self, directive: &str, token: &str) {
        if let Some((_, value)) = self
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
        {
            if !contains_token(value, token) {
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(token);
            }
        } else {
            self.directives
                .push((directive.to_string(), token.to_string()));
        }
    }

    pub(crate) fn set_directive(&mut self, directive: &str, value: &str) {
        if let Some((_, existing)) = self
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
        {
            *existing = value.to_string();
        } else {
            self.directives
                .push((directive.to_string(), value.to_string()));
        }
    }

    pub(crate) fn directive_value(&self, name: &str) -> Option<&str> {
        self.directives
            .iter()
            .find(|(directive, _)| directive == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.trim().is_empty())
    }

    pub(crate) fn has_directive(&self, name: &str) -> bool {
        self.directives
            .iter()
            .any(|(directive, _)| directive == name)
    }
}

impl FeatureOptions for CspOptions {
    type Error = CspOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_with_warnings().map(|_| ())
    }
}

impl CspOptions {
    pub fn validate_with_warnings(&self) -> Result<Vec<CspOptionsWarning>, CspOptionsError> {
        validation::validate_with_warnings(self)
    }

    #[cfg(test)]
    pub(crate) fn validate_token(directive: &str, token: &str) -> Result<(), CspOptionsError> {
        validation::validate_token(directive, token)
    }

    #[cfg(test)]
    pub(crate) fn validate_source_expression(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_source_expression(token)
    }

    #[cfg(test)]
    pub(crate) fn validate_source_expression_cached(
        token: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        validation::validate_source_expression_cached(token, cache)
    }

    #[cfg(test)]
    pub(crate) fn validate_strict_dynamic_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> Result<(), CspOptionsError> {
        validation::validate_strict_dynamic_host_sources(script_src, script_src_elem)
    }

    #[cfg(test)]
    pub(crate) fn strict_dynamic_has_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> bool {
        validation::strict_dynamic_has_host_sources(script_src, script_src_elem)
    }

    #[cfg(test)]
    pub(crate) fn validate_host_like_source(
        value: &str,
        original: &str,
    ) -> Result<(), CspOptionsError> {
        validation::validate_host_like_source(value, original)
    }

    #[cfg(test)]
    pub(crate) fn validate_wildcard_host(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_wildcard_host(token)
    }

    #[cfg(test)]
    pub(crate) fn validate_path_source(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_path_source(token)
    }

    #[cfg(test)]
    pub(crate) fn validate_directive_value(
        directive: &str,
        value: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        validation::validate_directive_value(directive, value, cache)
    }

    #[cfg(test)]
    pub(crate) fn enforce_scheme_restrictions(
        directive: &str,
        token: &str,
    ) -> Result<(), CspOptionsError> {
        validation::enforce_scheme_restrictions(directive, token)
    }

    #[cfg(test)]
    pub(crate) fn normalize_port_wildcard(
        candidate: String,
        original: &str,
    ) -> Result<String, CspOptionsError> {
        validation::normalize_port_wildcard(candidate, original)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_nonces(name: &str) -> bool {
        validation::directive_supports_nonces(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_hashes(name: &str) -> bool {
        validation::directive_supports_hashes(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_strict_dynamic(name: &str) -> bool {
        validation::directive_supports_strict_dynamic(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_unsafe_inline(name: &str) -> bool {
        validation::directive_supports_unsafe_inline(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_unsafe_eval(name: &str) -> bool {
        validation::directive_supports_unsafe_eval(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_unsafe_hashes(name: &str) -> bool {
        validation::directive_supports_unsafe_hashes(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_wasm_unsafe_eval(name: &str) -> bool {
        validation::directive_supports_wasm_unsafe_eval(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_supports_report_sample(name: &str) -> bool {
        validation::directive_supports_report_sample(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_is_script_family(name: &str) -> bool {
        validation::directive_is_script_family(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_is_style_family(name: &str) -> bool {
        validation::directive_is_style_family(name)
    }

    #[cfg(test)]
    pub(crate) fn directive_expects_sources(name: &str) -> bool {
        validation::directive_expects_sources(name)
    }

    #[cfg(test)]
    pub(crate) fn allows_empty_value(name: &str) -> bool {
        validation::allows_empty_value(name)
    }

    #[cfg(test)]
    pub(crate) fn contains_conflicting_none(tokens: &[&str]) -> bool {
        validation::contains_conflicting_none(tokens)
    }

    #[cfg(test)]
    pub(crate) fn is_permissive_default_source(value: &str) -> bool {
        validation::is_permissive_default_source(value)
    }

    #[cfg(test)]
    pub(crate) fn has_invalid_header_text(value: &str) -> bool {
        validation::has_invalid_header_text(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspOptionsWarning {
    pub severity: CspWarningSeverity,
    pub kind: CspOptionsWarningKind,
}

impl CspOptionsWarning {
    pub(crate) fn info(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Info,
            kind,
        }
    }

    pub(crate) fn warning(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Warning,
            kind,
        }
    }

    pub(crate) fn critical(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Critical,
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspWarningSeverity {
    Info,
    Warning,
    Critical,
}

impl CspWarningSeverity {
    pub(crate) fn max(self, other: Self) -> Self {
        use CspWarningSeverity::*;

        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Warning, _) | (_, Warning) => Warning,
            _ => Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspOptionsWarningKind {
    MissingWorkerSrcFallback,
    WeakWorkerSrcFallback,
    UpgradeInsecureRequestsWithoutBlockAllMixedContent,
    BlockAllMixedContentWithoutUpgradeInsecureRequests,
    RiskySchemes {
        directive: String,
        schemes: Vec<String>,
    },
}

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CspOptionsError {
    #[error("missing directives")]
    MissingDirectives,
    #[error("invalid directive name")]
    InvalidDirectiveName,
    #[error("invalid directive value")]
    InvalidDirectiveValue,
    #[error("invalid directive token")]
    InvalidDirectiveToken,
    #[error("invalid nonce source expression")]
    InvalidNonce,
    #[error("invalid hash source expression")]
    InvalidHash,
    #[error("'strict-dynamic' requires at least one nonce or hash source")]
    StrictDynamicRequiresNonceOrHash,
    #[error("'strict-dynamic' cannot be combined with unsafe-inline/unsafe-eval/unsafe-hashes")]
    StrictDynamicConflicts,
    #[error("'none' token cannot be combined with other sources")]
    ConflictingNoneToken,
    #[error("sandbox directive contains invalid token `{0}`")]
    InvalidSandboxToken(String),
    #[error("invalid source expression `{0}`")]
    InvalidSourceExpression(String),
    #[error("token `{0}` is not allowed in directive `{1}`")]
    TokenNotAllowedForDirective(String, String),
    #[error("'unsafe-hashes' in `{0}` requires at least one hash source expression")]
    UnsafeHashesRequireHashes(String),
    #[error("scheme `{1}` is not permitted in directive `{0}`")]
    DisallowedScheme(String, String),
    #[error("source expression `{0}` cannot use a wildcard port")]
    PortWildcardUnsupported(String),
    #[error("'strict-dynamic' cannot be combined with host or scheme sources")]
    StrictDynamicHostSourceConflict,
}
