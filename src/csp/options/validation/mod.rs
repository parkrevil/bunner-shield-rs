use std::collections::HashMap;

use crate::csp::options::config::{CspOptions, CspOptionsError, CspOptionsWarning};
use crate::csp::options::types::CspDirective;

mod directive_value;
mod source_expression;
mod strict_dynamic;

pub(crate) use directive_value::directive_expects_sources;
pub(crate) use source_expression::{has_invalid_header_text, is_permissive_default_source};

#[cfg(test)]
pub(crate) use directive_value::{
    allows_empty_value, contains_conflicting_none, directive_is_script_family,
    directive_is_style_family, directive_supports_hashes, directive_supports_nonces,
    directive_supports_report_sample, directive_supports_strict_dynamic,
    directive_supports_unsafe_eval, directive_supports_unsafe_hashes,
    directive_supports_unsafe_inline, directive_supports_wasm_unsafe_eval,
    enforce_scheme_restrictions, validate_directive_value, validate_token,
};

#[cfg(test)]
pub(crate) use source_expression::{
    normalize_port_wildcard, validate_host_like_source, validate_path_source,
    validate_source_expression, validate_source_expression_cached, validate_wildcard_host,
};

#[cfg(test)]
pub(crate) use strict_dynamic::{
    strict_dynamic_has_host_sources, validate_strict_dynamic_host_sources,
};

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

        directive_value::validate_directive_value(name, value, &mut token_cache)?;
    }

    let script_src = options.directive_value(CspDirective::ScriptSrc.as_str());
    let script_src_elem = options.directive_value(CspDirective::ScriptSrcElem.as_str());
    strict_dynamic::validate_strict_dynamic_rules(script_src, script_src_elem)?;
    strict_dynamic::validate_strict_dynamic_host_sources(script_src, script_src_elem)?;

    let mut warnings = Vec::new();
    options.validate_worker_fallback(&mut warnings)?;
    options.emit_mixed_content_dependency_warnings(&mut warnings);
    options.emit_risky_scheme_warnings(&mut warnings);

    Ok(warnings)
}
