use super::NormalizedHeaders;

mod from_pairs {
    use super::*;

    #[test]
    fn given_mixed_case_pairs_when_from_pairs_then_get_is_case_insensitive() {
        let pairs = vec![("X-Test".to_string(), "value".to_string())];

        let headers = NormalizedHeaders::from_pairs(pairs);

        assert_eq!(headers.get("x-test"), Some("value"));
    }
}

mod get {
    use super::*;

    #[test]
    fn given_missing_header_when_get_then_returns_none() {
        let headers =
            NormalizedHeaders::from_pairs(vec![("X-Trace".to_string(), "123".to_string())]);

        let result = headers.get("x-test");

        assert_eq!(result, None);
    }

    #[test]
    fn given_present_header_when_get_with_mixed_case_then_returns_value() {
        let headers = NormalizedHeaders::from_pairs(vec![
            ("X-App".to_string(), "core".to_string()),
            ("X-Env".to_string(), "prod".to_string()),
        ]);

        let result = headers.get("X-APP");

        assert_eq!(result, Some("core"));
    }

    #[test]
    fn given_multiple_headers_when_get_then_returns_matching_value() {
        let headers = NormalizedHeaders::from_pairs(vec![
            ("X-Env".to_string(), "stage".to_string()),
            ("X-Request-Id".to_string(), "abc123".to_string()),
            ("X-Env".to_string(), "prod".to_string()),
        ]);

        let result = headers.get("x-env");

        assert_eq!(result, Some("stage"));
    }
}
