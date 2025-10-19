use super::*;

mod format_sources {
    use super::*;

    #[test]
    fn given_sources_with_empty_segment_when_format_sources_then_skips_segment() {
        let formatted = format_sources([
            CspSource::from(""),
            CspSource::SelfKeyword,
            CspSource::Custom("".to_string()),
        ]);

        assert_eq!(formatted, "'self'");
    }
}

mod sanitize_token_input {
    use super::*;

    #[test]
    fn given_quoted_input_when_sanitize_token_input_then_returns_trimmed_value() {
        let sanitized = sanitize_token_input("  'token-value'  ".to_string());
        assert_eq!(sanitized, "token-value");
    }
}

mod contains_token {
    use super::*;

    #[test]
    fn given_existing_token_when_contains_token_then_returns_true() {
        assert!(contains_token("'self' 'nonce-abc'", "'self'"));
        assert!(!contains_token("'self' 'nonce-abc'", "'report-sample'"));
    }
}
