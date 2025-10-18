use super::*;

fn secret() -> [u8; 32] {
    [0x7F; 32]
}

mod issue {
    use super::*;

    #[test]
    fn given_valid_length_when_issue_then_returns_hex_token_of_requested_size() {
        let service = HmacCsrfService::new(secret());

        let token = service.issue(32).expect("issue should succeed");

        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn given_multiple_requests_when_issue_then_returns_distinct_tokens() {
        let service = HmacCsrfService::new(secret());

        let first = service.issue(16).expect("first issue should succeed");
        let second = service.issue(16).expect("second issue should succeed");

        assert_ne!(first, second);
    }

    #[test]
    fn given_zero_length_when_issue_then_returns_invalid_length_error() {
        let service = HmacCsrfService::new(secret());

        let error = service.issue(0).expect_err("expected invalid length error");

        assert_eq!(error, CsrfTokenError::InvalidTokenLength(0));
    }

    #[test]
    fn given_length_above_limit_when_issue_then_returns_invalid_length_error() {
        let service = HmacCsrfService::new(secret());

        let error = service
            .issue(100)
            .expect_err("expected invalid length error");

        assert_eq!(error, CsrfTokenError::InvalidTokenLength(100));
    }
}
