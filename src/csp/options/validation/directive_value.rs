use crate::csp::options::config::CspOptionsError;
use crate::csp::options::sandbox::SandboxToken;
use crate::csp::options::types::CspDirective;

use super::has_invalid_header_text;
use super::source_expression::validate_source_expression_cached;
use super::validate::TokenValidationCache;

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
        "upgrade-insecure-requests" | "sandbox"
    )
}

pub(crate) fn contains_conflicting_none(tokens: &[&str]) -> bool {
    tokens.contains(&"'none'") && tokens.len() > 1
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

fn validate_sandbox_tokens(value: &str) -> Result<(), CspOptionsError> {
    for token in value.split_whitespace() {
        if SandboxToken::parse(token).is_none() {
            return Err(CspOptionsError::InvalidSandboxToken(token.to_string()));
        }
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

#[cfg(test)]
#[path = "directive_value_test.rs"]
mod directive_value_test;
