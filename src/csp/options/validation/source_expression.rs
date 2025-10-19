use url::Url;

use crate::csp::options::config::CspOptionsError;

use super::TokenValidationCache;

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

#[cfg(test)]
#[path = "source_expression_test.rs"]
mod source_expression_test;
