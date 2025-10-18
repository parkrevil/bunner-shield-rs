use super::*;
use crate::tests_common as common;

mod origin {
    use super::*;

    #[test]
    fn given_matching_origin_when_validate_then_ok() {
        let headers = common::headers_with(&[("Origin", "https://example.com")]);
        let result = validate_origin(&headers, false, &["https://example.com"]);
        assert!(result.is_ok());
    }

    #[test]
    fn given_mismatched_scheme_when_validate_then_cross_origin() {
        let headers = common::headers_with(&[("Origin", "http://example.com")]);
        let err = validate_origin(&headers, false, &["https://example.com"])
            .expect_err("expected cross-origin error");
        assert_eq!(err, OriginCheckError::CrossOrigin);
    }

    #[test]
    fn given_default_ports_when_validate_then_match() {
        let h1 = common::headers_with(&[("Origin", "https://example.com")]);
        assert!(validate_origin(&h1, false, &["https://example.com:443"]).is_ok());

        let h2 = common::headers_with(&[("Origin", "http://example.com:80")]);
        assert!(validate_origin(&h2, false, &["http://example.com"]).is_ok());
    }

    #[test]
    fn given_null_or_empty_origin_when_fallback_disabled_then_missing_origin() {
        let h_null = common::headers_with(&[("Origin", "null")]);
        let err = validate_origin(&h_null, false, &["https://example.com"]) 
            .expect_err("expected missing origin");
        assert_eq!(err, OriginCheckError::MissingOrigin);

        let h_empty = common::headers_with(&[("Origin", " ")]);
        let err = validate_origin(&h_empty, false, &["https://example.com"]) 
            .expect_err("expected missing origin");
        assert_eq!(err, OriginCheckError::MissingOrigin);
    }

    #[test]
    fn given_mixed_case_header_names_when_validate_then_ok() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("oRiGiN".to_string(), "https://example.com".to_string());
        assert!(validate_origin(&headers, false, &["https://example.com"]).is_ok());
    }
}

mod referer_fallback {
    use super::*;

    #[test]
    fn given_referer_and_fallback_enabled_when_validate_then_ok() {
        let headers = common::headers_with(&[("Referer", "https://example.com/path?q=1#x")]);
        let result = validate_origin(&headers, true, &["https://example.com"]);
        assert!(result.is_ok());
    }

    #[test]
    fn given_referer_mismatch_when_validate_then_cross_origin() {
        let headers = common::headers_with(&[("Referer", "https://evil.com/whatever")]);
        let err = validate_origin(&headers, true, &["https://example.com"])
            .expect_err("expected cross-origin error");
        assert_eq!(err, OriginCheckError::CrossOrigin);
    }

    #[test]
    fn given_missing_origin_and_no_fallback_when_validate_then_missing_origin() {
        let headers = common::headers_with(&[]);
        let err = validate_origin(&headers, false, &["https://example.com"])
            .expect_err("expected missing origin error");
        assert_eq!(err, OriginCheckError::MissingOrigin);
    }

    #[test]
    fn given_missing_both_when_fallback_enabled_then_missing_referer() {
        let headers = common::headers_with(&[]);
        let err = validate_origin(&headers, true, &["https://example.com"])
            .expect_err("expected missing referer error");
        assert_eq!(err, OriginCheckError::MissingReferer);
    }
}

mod malformed {
    use super::*;

    #[test]
    fn given_malformed_origin_when_validate_then_invalid_origin_header() {
        let headers = common::headers_with(&[("Origin", "not a url")]);
        let err = validate_origin(&headers, false, &["https://example.com"])
            .expect_err("expected invalid origin header error");
        assert_eq!(err, OriginCheckError::InvalidHeader("Origin"));
    }

    #[test]
    fn given_malformed_referer_when_validate_then_invalid_referer_header() {
        let headers = common::headers_with(&[("Referer", "not a url")]);
        let err = validate_origin(&headers, true, &["https://example.com"])
            .expect_err("expected invalid referer header error");
        assert_eq!(err, OriginCheckError::InvalidHeader("Referer"));
    }
}
