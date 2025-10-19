use super::*;

mod validate_source_expression {
    use super::*;

    #[test]
    fn given_absolute_path_when_validate_source_expression_then_returns_ok() {
        validate_source_expression("/assets/static").expect("absolute paths should be accepted");
    }

    #[test]
    fn given_wildcard_host_when_validate_source_expression_then_returns_ok() {
        validate_source_expression("*.media.example").expect("wildcard hosts should be accepted");
    }

    #[test]
    fn given_whitespace_in_source_expression_when_validate_source_expression_then_returns_error() {
        let token = "example.com path";
        let error = validate_source_expression(token)
            .expect_err("whitespace should be rejected in source expressions");
        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }
}

mod normalize_port_wildcard {
    use super::*;

    #[test]
    fn given_port_wildcard_followed_by_path_when_normalize_then_returns_port_wildcard_error() {
        let error = normalize_port_wildcard(
            "https://example.com:*/path".to_string(),
            "https://example.com:*/path",
        )
        .expect_err("port wildcard should not be followed by a path");
        assert_eq!(
            error,
            CspOptionsError::PortWildcardUnsupported("https://example.com:*/path".to_string())
        );
    }
}
