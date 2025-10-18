use super::*;
use crate::tests_common as common;

fn secret() -> [u8; 32] {
    [0xAB; 32]
}

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_options() {
        let options = CsrfOptions::new(secret()).token_length(40);
        let executor = Csrf::new(options);

        let result = executor.options();

        let expected = CsrfOptions::new(secret()).token_length(40);
        assert_eq!(result.cookie_name, expected.cookie_name);
        assert_eq!(result.token_length, expected.token_length);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_valid_configuration_when_execute_then_sets_token_and_cookie_headers() {
        let secret = secret();
        let options = CsrfOptions::new(secret);
        let expected_service = HmacCsrfService::new(secret);
        let expected_token = expected_service
            .issue(64)
            .expect("expected issue to succeed");
        let executor = Csrf::new(options);
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(result.get("X-CSRF-Token"), Some(&expected_token.clone()));
        assert_eq!(
            result.get("Set-Cookie"),
            Some(&format!(
                "__Host-csrf-token={}; Path=/; Secure; HttpOnly; SameSite=Lax",
                expected_token
            ))
        );
    }

    #[test]
    fn given_invalid_token_length_when_execute_then_returns_token_generation_error() {
        let options = CsrfOptions::new(secret()).token_length(70);
        let mut headers = common::normalized_headers_from(&[]);
        let executor = Csrf::new(options);

        let error = executor
            .execute(&mut headers)
            .expect_err("expected token generation error");

        let expected = CsrfError::TokenGeneration(CsrfTokenError::InvalidTokenLength(70));
        assert_eq!(error.to_string(), expected.to_string());
    }
}
