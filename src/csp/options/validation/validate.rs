use std::collections::HashMap;

use crate::csp::options::config::{CspOptions, CspOptionsError, CspOptionsWarning};
use crate::csp::options::types::CspDirective;

use super::{directive_value, strict_dynamic};

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

#[cfg(test)]
#[path = "validate_test.rs"]
mod validate_test;
