use crate::csp::options::config::CspOptionsError;

pub(crate) fn validate_strict_dynamic_rules(
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
