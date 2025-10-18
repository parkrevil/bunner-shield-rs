use super::*;

mod hash_algorithm_prefix {
    use super::*;

    #[test]
    fn given_sha256_algorithm_when_prefix_then_returns_sha256_marker() {
        assert_eq!(CspHashAlgorithm::Sha256.prefix(), "sha256-");
    }

    #[test]
    fn given_sha512_algorithm_when_prefix_then_returns_sha512_marker() {
        assert_eq!(CspHashAlgorithm::Sha512.prefix(), "sha512-");
    }
}

mod directive_as_str {
    use super::*;

    #[test]
    fn given_default_src_directive_when_as_str_then_returns_default_src_name() {
        assert_eq!(CspDirective::DefaultSrc.as_str(), "default-src");
    }

    #[test]
    fn given_trusted_types_directive_when_as_str_then_returns_trusted_types_name() {
        assert_eq!(CspDirective::TrustedTypes.as_str(), "trusted-types");
    }
}

mod sandbox_token_from_str {
    use super::*;

    #[test]
    fn given_known_token_when_from_str_then_returns_matching_variant() {
        let token = SandboxToken::from_str("allow-popups");

        assert_eq!(token, Some(SandboxToken::AllowPopups));
    }

    #[test]
    fn given_unknown_token_when_from_str_then_returns_none() {
        let token = SandboxToken::from_str("allow-everything");

        assert!(token.is_none());
    }
}

mod trusted_types_policy_new {
    use super::*;

    #[test]
    fn given_valid_name_when_new_then_returns_policy_instance() {
        let policy = TrustedTypesPolicy::new("trustedPolicy").expect("policy should be valid");

        assert_eq!(policy.as_str(), "trustedPolicy");
    }

    #[test]
    fn given_empty_name_when_new_then_returns_empty_error() {
        let error = TrustedTypesPolicy::new("").expect_err("expected empty error");

        assert_eq!(error, TrustedTypesPolicyError::Empty);
    }

    #[test]
    fn given_invalid_characters_when_new_then_returns_invalid_name_error() {
        let error = TrustedTypesPolicy::new("1policy").expect_err("expected invalid name error");

        assert_eq!(
            error,
            TrustedTypesPolicyError::InvalidName("1policy".to_string())
        );
    }
}

mod trusted_types_token_display {
    use super::*;

    #[test]
    fn given_allow_duplicates_token_when_into_string_then_returns_literal() {
        let token = TrustedTypesToken::allow_duplicates();

        assert_eq!(token.into_string(), "'allow-duplicates'");
    }

    #[test]
    fn given_policy_token_when_into_string_then_returns_policy_name() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("policy should be valid");
        let token = TrustedTypesToken::from(policy);

        assert_eq!(token.into_string(), "appPolicy");
    }
}

mod csp_source_display {
    use super::*;

    #[test]
    fn given_nonce_source_with_padding_when_display_then_trims_and_formats_value() {
        let source = CspSource::Nonce("  token-value  ".to_string());

        assert_eq!(source.to_string(), "'nonce-token-value'");
    }

    #[test]
    fn given_hash_source_with_quotes_when_display_then_sanitizes_token() {
        let source = CspSource::Hash {
            algorithm: CspHashAlgorithm::Sha384,
            value: " 'abc' ".to_string(),
        };

        assert_eq!(source.to_string(), "'sha384-abc'");
    }
}

mod csp_nonce_manager {
    use super::*;

    #[test]
    fn given_zero_length_when_with_size_then_returns_invalid_length_error() {
        let error = CspNonceManager::with_size(0).expect_err("expected invalid length error");

        assert_eq!(error, CspNonceManagerError::InvalidLength);
    }

    #[test]
    fn given_manager_when_issue_header_value_then_returns_nonce_prefix() {
        let manager = CspNonceManager::with_size(8).expect("manager should be created");

        let header = manager.issue_header_value();

        assert!(header.starts_with("'nonce-"));
        assert!(header.len() > 8);
    }
}

mod generate_nonce_with_size {
    use super::*;

    #[test]
    fn given_zero_length_when_generate_nonce_with_size_then_returns_empty_string() {
        let nonce = CspOptions::generate_nonce_with_size(0);

        assert!(nonce.is_empty());
    }
}

mod options_directives {
    use super::*;

    #[test]
    fn given_sources_with_duplicates_when_default_src_then_stores_unique_sources() {
        let options = CspOptions::new().default_src([
            CspSource::SelfKeyword,
            CspSource::SelfKeyword,
            CspSource::Wildcard,
        ]);

        assert_eq!(
            options.directives,
            vec![("default-src".to_string(), "'self' *".to_string())]
        );
    }

    #[test]
    fn given_nonce_with_quotes_when_script_src_nonce_then_sanitizes_token_entry() {
        let options = CspOptions::new().script_src_nonce(" 'nonce value' ");

        assert_eq!(
            options.directives,
            vec![("script-src".to_string(), "'nonce-nonce value'".to_string())]
        );
    }
}
