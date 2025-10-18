use std::collections::HashMap;

use url::Url;

use super::config::{CspOptions, CspOptionsError, CspOptionsWarning};
use super::sandbox::SandboxToken;
use super::types::CspDirective;

pub(crate) type TokenValidationCache = HashMap<String, Result<(), CspOptionsError>>;

pub(crate) fn validate_with_warnings(
    options: &CspOptions,
) -> Result<Vec<CspOptionsWarning>, CspOptionsError> {
    if options.directives.is_empty() {
        return Err(CspOptionsError::MissingDirectives);
    }

    let mut token_cache = TokenValidationCache::new();

    for (name, value) in &options.directives {
        if !CspOptions::is_valid_directive_name(name) {
            return Err(CspOptionsError::InvalidDirectiveName);
        }

        validate_directive_value(name, value, &mut token_cache)?;
    }

    let script_src = options.directive_value(CspDirective::ScriptSrc.as_str());
    let script_src_elem = options.directive_value(CspDirective::ScriptSrcElem.as_str());
    validate_strict_dynamic_rules(script_src, script_src_elem)?;
    validate_strict_dynamic_host_sources(script_src, script_src_elem)?;

    let mut warnings = Vec::new();
    options.validate_worker_fallback(&mut warnings)?;
    options.emit_mixed_content_dependency_warnings(&mut warnings);
    options.emit_risky_scheme_warnings(&mut warnings);

    Ok(warnings)
}

pub(crate) fn validate_directive_value(
    name: &str,
    value: &str,
    cache: &mut TokenValidationCache,
) -> Result<(), CspOptionsError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        if allows_empty_value(name) {
            return Ok(());
        }

        return Err(CspOptionsError::InvalidDirectiveValue);
    }

    if has_invalid_header_text(value) {
        return Err(CspOptionsError::InvalidDirectiveToken);
    }

    if name == CspDirective::Sandbox.as_str() {
        return validate_sandbox_tokens(trimmed);
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();

    if directive_expects_sources(name) && contains_conflicting_none(&tokens) {
        return Err(CspOptionsError::ConflictingNoneToken);
    }

    for &token in &tokens {
        validate_token(name, token)?;

        if directive_expects_sources(name) && !token.starts_with('\'') {
            validate_source_expression_cached(token, cache)?;
            enforce_scheme_restrictions(name, token)?;
        }
    }

    validate_unsafe_hashes_semantics(name, &tokens)?;

    Ok(())
}

pub(crate) fn validate_token(directive: &str, token: &str) -> Result<(), CspOptionsError> {
    if token.is_empty() {
        return Err(CspOptionsError::InvalidDirectiveValue);
    }

    if let Some(rest) = token.strip_prefix("'nonce-") {
        if !directive_supports_nonces(directive) {
            return Err(CspOptionsError::TokenNotAllowedForDirective(
                token.to_string(),
                directive.to_string(),
            ));
        }
        return validate_nonce(rest);
    }

    if let Some(rest) = token.strip_prefix("'sha256-") {
        if !directive_supports_hashes(directive) {
            return Err(CspOptionsError::TokenNotAllowedForDirective(
                token.to_string(),
                directive.to_string(),
            ));
        }
        return validate_hash(rest, 44);
    }

    if let Some(rest) = token.strip_prefix("'sha384-") {
        if !directive_supports_hashes(directive) {
            return Err(CspOptionsError::TokenNotAllowedForDirective(
                token.to_string(),
                directive.to_string(),
            ));
        }
        return validate_hash(rest, 64);
    }

    if let Some(rest) = token.strip_prefix("'sha512-") {
        if !directive_supports_hashes(directive) {
            return Err(CspOptionsError::TokenNotAllowedForDirective(
                token.to_string(),
                directive.to_string(),
            ));
        }
        return validate_hash(rest, 88);
    }

    if token.starts_with('"') || token.ends_with('"') {
        return Err(CspOptionsError::InvalidDirectiveToken);
    }

    if token.starts_with('\'') && !token.ends_with('\'') {
        return Err(CspOptionsError::InvalidDirectiveToken);
    }

    if token.chars().any(|ch| ch.is_control()) {
        return Err(CspOptionsError::InvalidDirectiveToken);
    }

    match token {
        "'unsafe-inline'" => {
            if !directive_supports_unsafe_inline(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
        }
        "'unsafe-eval'" => {
            if !directive_supports_unsafe_eval(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
        }
        "'unsafe-hashes'" => {
            if !directive_supports_unsafe_hashes(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
        }
        "'wasm-unsafe-eval'" => {
            if !directive_supports_wasm_unsafe_eval(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
        }
        "'report-sample'" => {
            if !directive_supports_report_sample(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
        }
        _ => {}
    }

    if token == "'strict-dynamic'" && !directive_supports_strict_dynamic(directive) {
        return Err(CspOptionsError::TokenNotAllowedForDirective(
            token.to_string(),
            directive.to_string(),
        ));
    }

    Ok(())
}

fn validate_nonce(rest: &str) -> Result<(), CspOptionsError> {
    let encoded = rest
        .strip_suffix('\'')
        .ok_or(CspOptionsError::InvalidNonce)?;

    if encoded.len() < 22 {
        return Err(CspOptionsError::InvalidNonce);
    }

    if !encoded
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
    {
        return Err(CspOptionsError::InvalidNonce);
    }

    Ok(())
}

fn validate_hash(rest: &str, expected_len: usize) -> Result<(), CspOptionsError> {
    let encoded = rest
        .strip_suffix('\'')
        .ok_or(CspOptionsError::InvalidHash)?;

    if encoded.len() != expected_len {
        return Err(CspOptionsError::InvalidHash);
    }

    if !encoded
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
    {
        return Err(CspOptionsError::InvalidHash);
    }

    Ok(())
}

pub(crate) fn directive_supports_nonces(name: &str) -> bool {
    matches!(
        name,
        "script-src"
            | "script-src-elem"
            | "script-src-attr"
            | "style-src"
            | "style-src-elem"
            | "style-src-attr"
    )
}

pub(crate) fn directive_supports_hashes(name: &str) -> bool {
    directive_supports_nonces(name)
}

pub(crate) fn directive_supports_strict_dynamic(name: &str) -> bool {
    matches!(name, "script-src" | "script-src-elem")
}

pub(crate) fn directive_supports_unsafe_inline(name: &str) -> bool {
    directive_is_script_family(name) || directive_is_style_family(name)
}

pub(crate) fn directive_supports_unsafe_eval(name: &str) -> bool {
    matches!(name, "script-src" | "script-src-elem")
}

pub(crate) fn directive_supports_unsafe_hashes(name: &str) -> bool {
    matches!(name, "script-src" | "style-src")
}

pub(crate) fn directive_supports_wasm_unsafe_eval(name: &str) -> bool {
    matches!(name, "script-src" | "script-src-elem")
}

pub(crate) fn directive_supports_report_sample(name: &str) -> bool {
    directive_is_script_family(name) || directive_is_style_family(name)
}

pub(crate) fn directive_is_script_family(name: &str) -> bool {
    matches!(name, "script-src" | "script-src-elem" | "script-src-attr")
}

pub(crate) fn directive_is_style_family(name: &str) -> bool {
    matches!(name, "style-src" | "style-src-elem" | "style-src-attr")
}

pub(crate) fn directive_expects_sources(name: &str) -> bool {
    matches!(
        name,
        "default-src"
            | "script-src"
            | "script-src-elem"
            | "script-src-attr"
            | "style-src"
            | "style-src-elem"
            | "style-src-attr"
            | "img-src"
            | "connect-src"
            | "font-src"
            | "frame-src"
            | "worker-src"
            | "media-src"
            | "manifest-src"
            | "object-src"
            | "navigate-to"
            | "base-uri"
            | "form-action"
            | "frame-ancestors"
    )
}

pub(crate) fn allows_empty_value(name: &str) -> bool {
    matches!(
        name,
        "upgrade-insecure-requests" | "block-all-mixed-content" | "sandbox"
    )
}

pub(crate) fn contains_conflicting_none(tokens: &[&str]) -> bool {
    tokens.contains(&"'none'") && tokens.len() > 1
}

fn validate_sandbox_tokens(value: &str) -> Result<(), CspOptionsError> {
    for token in value.split_whitespace() {
        if SandboxToken::parse(token).is_none() {
            return Err(CspOptionsError::InvalidSandboxToken(token.to_string()));
        }
    }

    Ok(())
}

fn validate_strict_dynamic_rules(
    script_src: Option<&str>,
    script_src_elem: Option<&str>,
) -> Result<(), CspOptionsError> {
    let mut has_strict_dynamic = false;
    let mut has_nonce_or_hash = false;
    let mut has_conflicts = false;

    for directive in [script_src, script_src_elem].into_iter().flatten() {
        for token in directive.split_whitespace() {
            match token {
                "'strict-dynamic'" => has_strict_dynamic = true,
                "'unsafe-inline'" | "'unsafe-eval'" | "'unsafe-hashes'" => has_conflicts = true,
                _ => {
                    if token.starts_with("'nonce-")
                        || token.starts_with("'sha256-")
                        || token.starts_with("'sha384-")
                        || token.starts_with("'sha512-")
                    {
                        has_nonce_or_hash = true;
                    }
                }
            }
        }
    }

    if has_strict_dynamic {
        if !has_nonce_or_hash {
            return Err(CspOptionsError::StrictDynamicRequiresNonceOrHash);
        }

        if has_conflicts {
            return Err(CspOptionsError::StrictDynamicConflicts);
        }
    }

    Ok(())
}

pub(crate) fn strict_dynamic_has_host_sources(
    script_src: Option<&str>,
    script_src_elem: Option<&str>,
) -> bool {
    let mut has_strict_dynamic = false;
    let mut has_host_like_tokens = false;

    for directive in [script_src, script_src_elem].into_iter().flatten() {
        for token in directive.split_whitespace() {
            match token {
                "'strict-dynamic'" => has_strict_dynamic = true,
                _ if token.starts_with("'nonce-") || token.starts_with("'sha256-") => {}
                _ if token.starts_with("'sha384-") || token.starts_with("'sha512-") => {}
                "'unsafe-inline'" | "'unsafe-eval'" | "'unsafe-hashes'" | "'wasm-unsafe-eval'" => {}
                "'report-sample'" => {}
                "'self'" => has_host_like_tokens = true,
                _ if token.starts_with('\'') => {}
                _ => has_host_like_tokens = true,
            }
        }
    }

    has_strict_dynamic && has_host_like_tokens
}

pub(crate) fn validate_strict_dynamic_host_sources(
    script_src: Option<&str>,
    script_src_elem: Option<&str>,
) -> Result<(), CspOptionsError> {
    if strict_dynamic_has_host_sources(script_src, script_src_elem) {
        Err(CspOptionsError::StrictDynamicHostSourceConflict)
    } else {
        Ok(())
    }
}

pub(crate) fn enforce_scheme_restrictions(
    directive: &str,
    token: &str,
) -> Result<(), CspOptionsError> {
    if let Some(scheme) = token.strip_suffix(':') {
        if scheme.contains('/') {
            return Ok(());
        }

        let lowered = scheme.to_ascii_lowercase();
        const DISALLOWED_SCHEMES: [&str; 2] = ["javascript", "vbscript"];

        if DISALLOWED_SCHEMES.contains(&lowered.as_str()) {
            return Err(CspOptionsError::DisallowedScheme(
                directive.to_string(),
                lowered,
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_unsafe_hashes_semantics(
    directive: &str,
    tokens: &[&str],
) -> Result<(), CspOptionsError> {
    if !tokens.contains(&"'unsafe-hashes'") {
        return Ok(());
    }

    let has_hash_token = tokens.iter().any(|token| {
        token.starts_with("'sha256-")
            || token.starts_with("'sha384-")
            || token.starts_with("'sha512-")
    });

    if has_hash_token {
        Ok(())
    } else {
        Err(CspOptionsError::UnsafeHashesRequireHashes(
            directive.to_string(),
        ))
    }
}

pub(crate) fn validate_source_expression_cached(
    token: &str,
    cache: &mut TokenValidationCache,
) -> Result<(), CspOptionsError> {
    if let Some(result) = cache.get(token) {
        return result.clone();
    }

    let result = validate_source_expression(token);
    cache.insert(token.to_string(), result.clone());
    result
}

pub(crate) fn validate_source_expression(token: &str) -> Result<(), CspOptionsError> {
    if token == "*" {
        return Ok(());
    }

    if token
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
    }

    if token.ends_with(':') && !token.contains('/') {
        return validate_scheme_source(token);
    }

    if token.starts_with('/') {
        return validate_path_source(token);
    }

    if token.starts_with("*.") {
        return validate_wildcard_host(token);
    }

    validate_host_source(token)
}

fn validate_scheme_source(token: &str) -> Result<(), CspOptionsError> {
    let scheme = token.trim_end_matches(':');

    let mut chars = scheme.chars();

    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return Err(CspOptionsError::InvalidSourceExpression(token.to_string())),
    }

    if chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
        Ok(())
    } else {
        Err(CspOptionsError::InvalidSourceExpression(token.to_string()))
    }
}

fn validate_host_source(token: &str) -> Result<(), CspOptionsError> {
    validate_host_like_source(token, token)
}

pub(crate) fn validate_host_like_source(
    value: &str,
    original: &str,
) -> Result<(), CspOptionsError> {
    let base_candidate = if value.contains("//") {
        value.to_string()
    } else {
        format!("https://{}", value)
    };

    let candidate = normalize_port_wildcard(base_candidate, original)?;

    let parsed = Url::parse(&candidate)
        .map_err(|_| CspOptionsError::InvalidSourceExpression(original.to_string()))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CspOptionsError::InvalidSourceExpression(
            original.to_string(),
        ));
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CspOptionsError::InvalidSourceExpression(
            original.to_string(),
        ));
    }

    if let Some(host) = parsed.host_str() {
        if host.is_empty() {
            return Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ));
        }
    } else {
        return Err(CspOptionsError::InvalidSourceExpression(
            original.to_string(),
        ));
    }

    let path = parsed.path();
    if !path.is_empty()
        && path != "/"
        && (!path.starts_with('/') || path.chars().any(|ch| ch.is_control()))
    {
        return Err(CspOptionsError::InvalidSourceExpression(
            original.to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn normalize_port_wildcard(
    candidate: String,
    original: &str,
) -> Result<String, CspOptionsError> {
    if let Some(index) = candidate.find(":*") {
        let after = &candidate[index + 2..];
        if after.is_empty() || after.starts_with('/') {
            Err(CspOptionsError::PortWildcardUnsupported(
                original.to_string(),
            ))
        } else {
            Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ))
        }
    } else {
        Ok(candidate)
    }
}

pub(crate) fn validate_wildcard_host(token: &str) -> Result<(), CspOptionsError> {
    let rest = &token[2..];
    if rest.is_empty() {
        return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
    }

    if rest.contains('*') {
        return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
    }

    validate_host_like_source(rest, token)
}

pub(crate) fn validate_path_source(token: &str) -> Result<(), CspOptionsError> {
    if token
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
    }

    if token.starts_with('/') {
        Ok(())
    } else {
        Err(CspOptionsError::InvalidSourceExpression(token.to_string()))
    }
}

pub(crate) fn is_permissive_default_source(value: &str) -> bool {
    value.split_whitespace().any(|token| token == "*")
}

pub(crate) fn has_invalid_header_text(value: &str) -> bool {
    value.contains(['\r', '\n'])
}
