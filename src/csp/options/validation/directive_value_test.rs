use super::*;

mod validate_directive_value {
    use super::*;

    #[test]
    fn given_multiline_value_when_validate_directive_value_then_returns_invalid_token() {
        let mut cache = TokenValidationCache::default();
        let error = validate_directive_value(
            CspDirective::ScriptSrc.as_str(),
            "value\r\nnext",
            &mut cache,
        )
        .expect_err("embedded newlines are disallowed");

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_unsafe_hashes_without_hash_when_validate_directive_value_then_returns_error() {
        let mut cache = TokenValidationCache::default();
        let error = validate_directive_value(
            CspDirective::ScriptSrc.as_str(),
            "'unsafe-hashes'",
            &mut cache,
        )
        .expect_err("unsafe-hashes requires a hash expression");

        assert_eq!(
            error,
            CspOptionsError::UnsafeHashesRequireHashes(
                CspDirective::ScriptSrc.as_str().to_string()
            )
        );
    }
}

mod validate_token {
    use super::*;

    #[test]
    fn given_nonce_without_closing_quote_when_validate_token_then_returns_invalid_nonce() {
        let error = validate_token("script-src", "'nonce-abcd")
            .expect_err("nonce tokens require a closing quote");
        assert_eq!(error, CspOptionsError::InvalidNonce);
    }
}

mod enforce_scheme_restrictions {
    use super::*;

    #[test]
    fn given_disallowed_scheme_when_enforce_scheme_restrictions_then_returns_error() {
        let error = enforce_scheme_restrictions("script-src", "javascript:")
            .expect_err("javascript scheme should be rejected");
        match error {
            CspOptionsError::DisallowedScheme(directive, scheme) => {
                assert_eq!(directive, "script-src".to_string());
                assert_eq!(scheme, "javascript".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
