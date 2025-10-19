use super::*;
use std::borrow::Cow;

mod to_string {
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

    #[test]
    fn given_literal_variants_when_display_then_matches_expected_values() {
        let cases = [
            (CspSource::SelfKeyword, "'self'"),
            (CspSource::None, "'none'"),
            (CspSource::UnsafeInline, "'unsafe-inline'"),
            (CspSource::UnsafeEval, "'unsafe-eval'"),
            (CspSource::UnsafeHashes, "'unsafe-hashes'"),
            (CspSource::WasmUnsafeEval, "'wasm-unsafe-eval'"),
            (CspSource::StrictDynamic, "'strict-dynamic'"),
            (CspSource::ReportSample, "'report-sample'"),
            (CspSource::Wildcard, "*"),
            (CspSource::Scheme(Cow::Borrowed("data")), "data:"),
            (
                CspSource::Host(Cow::Borrowed("cdn.example.com")),
                "cdn.example.com",
            ),
            (
                CspSource::Custom("custom-token".to_string()),
                "custom-token",
            ),
        ];

        for (source, expected) in cases {
            assert_eq!(source.to_string(), expected);
        }
    }
}

mod from_impls {
    use super::*;

    #[test]
    fn given_str_when_from_then_returns_custom_source() {
        let source = CspSource::from("inline-script");
        assert!(matches!(source, CspSource::Custom(value) if value == "inline-script"));
    }

    #[test]
    fn given_string_when_from_then_returns_custom_source() {
        let source = CspSource::from("cdn".to_string());
        assert!(matches!(source, CspSource::Custom(value) if value == "cdn"));
    }

    #[test]
    fn given_nonce_when_from_then_returns_nonce_variant() {
        let nonce = CspNonce {
            value: "nonce-value".to_string(),
        };
        let source = CspSource::from(nonce.clone());
        assert!(matches!(source, CspSource::Nonce(value) if value == nonce.value));
    }
}
