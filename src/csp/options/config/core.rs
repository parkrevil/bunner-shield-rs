use std::collections::{HashMap, HashSet};

use crate::csp::options::{
    nonce::{self, CspNonceManager},
    runtime_nonce::RuntimeNonceConfig,
    sources::CspSource,
    types::CspDirective,
    utils::{contains_token, format_sources, sanitize_token_input},
    validation,
};
use crate::executor::FeatureOptions;

use super::errors::CspOptionsError;
use super::warnings::{CspOptionsWarning, CspOptionsWarningKind, CspWarningSeverity};

#[cfg(test)]
use crate::csp::options::validation::TokenValidationCache;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportToMergeStrategy {
    #[default]
    FirstWins,
    LastWins,
    Union,
}

#[derive(Debug, Clone, Default)]
pub struct CspOptions {
    pub(crate) directives: Vec<(String, String)>,
    pub(crate) runtime_nonce: Option<RuntimeNonceConfig>,
    pub(crate) report_to_merge_strategy: ReportToMergeStrategy,
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

    pub(crate) fn merge_runtime_nonce(&mut self, other: &CspOptions) {
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

    pub(crate) fn set_flag_directive(&mut self, directive: CspDirective) {
        self.set_directive(directive.as_str(), "");
    }

    pub fn generate_nonce() -> String {
        nonce::generate_nonce()
    }

    pub fn generate_nonce_with_size(byte_len: usize) -> String {
        nonce::generate_nonce_with_size(byte_len)
    }

    pub fn report_to_merge_strategy(mut self, strategy: ReportToMergeStrategy) -> Self {
        self.report_to_merge_strategy = strategy;
        self
    }

    pub(crate) fn is_valid_directive_name(name: &str) -> bool {
        CspDirective::ALL
            .iter()
            .any(|directive| directive.as_str() == name)
    }

    pub fn header_value(&self) -> String {
        let mut directives: Vec<(String, Vec<String>)> = self
            .directives
            .iter()
            .map(|(name, value)| {
                let tokens: Vec<String> = if value.trim().is_empty() {
                    Vec::new()
                } else {
                    value
                        .split_whitespace()
                        .map(|token| token.to_string())
                        .collect()
                };
                (name.clone(), tokens)
            })
            .collect();

        directives.sort_by(|(left, _), (right, _)| left.cmp(right));

        directives
            .into_iter()
            .map(|(name, mut tokens)| {
                if tokens.is_empty() {
                    return name;
                }

                tokens.sort();
                format!("{} {}", name, tokens.join(" "))
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

    pub fn validate_with_warnings(&self) -> Result<Vec<CspOptionsWarning>, CspOptionsError> {
        validation::validate_with_warnings(self)
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

    pub(crate) fn validate_worker_fallback(
        &self,
        warnings: &mut Vec<CspOptionsWarning>,
    ) -> Result<(), CspOptionsError> {
        if self
            .directive_value(CspDirective::WorkerSrc.as_str())
            .is_some()
        {
            return Ok(());
        }

        let has_script = self
            .directive_value(CspDirective::ScriptSrc.as_str())
            .is_some();
        if has_script {
            return Ok(());
        }

        if let Some(default_value) = self.directive_value(CspDirective::DefaultSrc.as_str()) {
            if validation::is_permissive_default_source(default_value) {
                warnings.push(CspOptionsWarning::warning(
                    CspOptionsWarningKind::WeakWorkerSrcFallback,
                ));
            }
            return Ok(());
        }

        warnings.push(CspOptionsWarning::critical(
            CspOptionsWarningKind::MissingWorkerSrcFallback,
        ));
        Ok(())
    }

    pub(crate) fn emit_mixed_content_dependency_warnings(
        &self,
        warnings: &mut Vec<CspOptionsWarning>,
    ) {
        let has_upgrade = self.has_directive(CspDirective::UpgradeInsecureRequests.as_str());
        let has_block = self.has_directive(CspDirective::BlockAllMixedContent.as_str());

        if has_upgrade && !has_block {
            warnings.push(CspOptionsWarning::warning(
                CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
            ));
        }

        if has_block && !has_upgrade {
            warnings.push(CspOptionsWarning::warning(
                CspOptionsWarningKind::BlockAllMixedContentWithoutUpgradeInsecureRequests,
            ));
        }
    }

    pub(crate) fn emit_risky_scheme_warnings(&self, warnings: &mut Vec<CspOptionsWarning>) {
        // Base schemes we consider potentially risky. Final severity can vary per directive.
        const RISKY_SCHEMES: [&str; 3] = ["data:", "blob:", "filesystem:"];

        fn scheme_severity_for_directive(
            directive: &str,
            scheme: &str,
        ) -> Option<CspWarningSeverity> {
            // Normalize scheme without trailing colon
            let s = scheme.trim_end_matches(':');

            match s {
                // data: URLs are extremely risky for script-like and navigation directives,
                // but more common (still risky) for media/img/fonts.
                "data" => {
                    if matches!(
                        directive,
                        "script-src" | "script-src-elem" | "script-src-attr"
                    ) || matches!(
                        directive,
                        "object-src"
                            | "frame-src"
                            | "frame-ancestors"
                            | "navigate-to"
                            | "base-uri"
                            | "form-action"
                    ) {
                        Some(CspWarningSeverity::Critical)
                    } else if matches!(
                        directive,
                        "img-src" | "media-src" | "font-src" | "manifest-src"
                    ) {
                        Some(CspWarningSeverity::Warning)
                    } else {
                        // default-src and other source lists: warn by default
                        Some(CspWarningSeverity::Warning)
                    }
                }
                // blob: is frequently used legitimately but can still widen attack surface.
                "blob" => {
                    if matches!(
                        directive,
                        "script-src" | "script-src-elem" | "script-src-attr" | "connect-src"
                    ) {
                        Some(CspWarningSeverity::Warning)
                    } else {
                        // For img/media/font/etc., treat as informational.
                        Some(CspWarningSeverity::Info)
                    }
                }
                // filesystem: considered highly risky broadly.
                "filesystem" => Some(CspWarningSeverity::Critical),
                _ => None,
            }
        }

        struct SchemeAggregation {
            schemes: HashSet<String>,
            severity: CspWarningSeverity,
        }

        let mut aggregated: HashMap<String, SchemeAggregation> = HashMap::new();

        for (directive, value) in &self.directives {
            if !validation::directive_expects_sources(directive) {
                continue;
            }

            for token in value.split_whitespace() {
                let lowered = token.to_ascii_lowercase();

                for &scheme in RISKY_SCHEMES.iter() {
                    if lowered.starts_with(scheme)
                        && let Some(severity) = scheme_severity_for_directive(directive, scheme)
                    {
                        let entry = aggregated.entry(directive.clone()).or_insert_with(|| {
                            SchemeAggregation {
                                schemes: std::collections::HashSet::new(),
                                severity: CspWarningSeverity::Info,
                            }
                        });
                        entry.severity = entry.severity.max(severity);
                        entry
                            .schemes
                            .insert(scheme.trim_end_matches(':').to_string());
                    }
                }
            }
        }

        let mut aggregated_entries: Vec<_> = aggregated.into_iter().collect();
        aggregated_entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (directive, entry) in aggregated_entries {
            let mut schemes: Vec<String> = entry.schemes.into_iter().collect();
            schemes.sort();

            let kind = CspOptionsWarningKind::RiskySchemes { directive, schemes };
            let warning = match entry.severity {
                CspWarningSeverity::Critical => CspOptionsWarning::critical(kind),
                CspWarningSeverity::Warning => CspOptionsWarning::warning(kind),
                CspWarningSeverity::Info => CspOptionsWarning::info(kind),
            };

            warnings.push(warning);
        }
    }
}

impl FeatureOptions for CspOptions {
    type Error = CspOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_with_warnings().map(|_| ())
    }
}

#[cfg(test)]
impl CspOptions {
    pub(crate) fn validate_token(directive: &str, token: &str) -> Result<(), CspOptionsError> {
        validation::validate_token(directive, token)
    }

    pub(crate) fn validate_source_expression(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_source_expression(token)
    }

    pub(crate) fn validate_source_expression_cached(
        token: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        validation::validate_source_expression_cached(token, cache)
    }

    pub(crate) fn validate_strict_dynamic_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> Result<(), CspOptionsError> {
        validation::validate_strict_dynamic_host_sources(script_src, script_src_elem)
    }

    pub(crate) fn strict_dynamic_has_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> bool {
        validation::strict_dynamic_has_host_sources(script_src, script_src_elem)
    }

    pub(crate) fn validate_host_like_source(
        value: &str,
        original: &str,
    ) -> Result<(), CspOptionsError> {
        validation::validate_host_like_source(value, original)
    }

    pub(crate) fn validate_wildcard_host(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_wildcard_host(token)
    }

    pub(crate) fn validate_path_source(token: &str) -> Result<(), CspOptionsError> {
        validation::validate_path_source(token)
    }

    pub(crate) fn validate_directive_value(
        directive: &str,
        value: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        validation::validate_directive_value(directive, value, cache)
    }

    pub(crate) fn enforce_scheme_restrictions(
        directive: &str,
        token: &str,
    ) -> Result<(), CspOptionsError> {
        validation::enforce_scheme_restrictions(directive, token)
    }

    pub(crate) fn normalize_port_wildcard(
        candidate: String,
        original: &str,
    ) -> Result<String, CspOptionsError> {
        validation::normalize_port_wildcard(candidate, original)
    }

    pub(crate) fn directive_supports_nonces(name: &str) -> bool {
        validation::directive_supports_nonces(name)
    }

    pub(crate) fn directive_supports_hashes(name: &str) -> bool {
        validation::directive_supports_hashes(name)
    }

    pub(crate) fn directive_supports_strict_dynamic(name: &str) -> bool {
        validation::directive_supports_strict_dynamic(name)
    }

    pub(crate) fn directive_supports_unsafe_inline(name: &str) -> bool {
        validation::directive_supports_unsafe_inline(name)
    }

    pub(crate) fn directive_supports_unsafe_eval(name: &str) -> bool {
        validation::directive_supports_unsafe_eval(name)
    }

    pub(crate) fn directive_supports_unsafe_hashes(name: &str) -> bool {
        validation::directive_supports_unsafe_hashes(name)
    }

    pub(crate) fn directive_supports_wasm_unsafe_eval(name: &str) -> bool {
        validation::directive_supports_wasm_unsafe_eval(name)
    }

    pub(crate) fn directive_supports_report_sample(name: &str) -> bool {
        validation::directive_supports_report_sample(name)
    }

    pub(crate) fn directive_is_script_family(name: &str) -> bool {
        validation::directive_is_script_family(name)
    }

    pub(crate) fn directive_is_style_family(name: &str) -> bool {
        validation::directive_is_style_family(name)
    }

    pub(crate) fn directive_expects_sources(name: &str) -> bool {
        validation::directive_expects_sources(name)
    }

    pub(crate) fn allows_empty_value(name: &str) -> bool {
        validation::allows_empty_value(name)
    }

    pub(crate) fn contains_conflicting_none(tokens: &[&str]) -> bool {
        validation::contains_conflicting_none(tokens)
    }

    pub(crate) fn is_permissive_default_source(value: &str) -> bool {
        validation::is_permissive_default_source(value)
    }

    pub(crate) fn has_invalid_header_text(value: &str) -> bool {
        validation::has_invalid_header_text(value)
    }
}

#[cfg(test)]
#[path = "core_test.rs"]
mod core_test;
