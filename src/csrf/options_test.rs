use super::*;

fn secret() -> [u8; 32] {
    [0x11; 32]
}

mod new {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_sets_secure_cookie_defaults() {
        let options = CsrfOptions::new(secret());

        assert_eq!(options.cookie_name, "__Host-csrf-token");
        assert_eq!(options.token_length, 64);
    }
}

mod cookie_name {
    use super::*;

    #[test]
    fn given_custom_cookie_name_when_cookie_name_then_updates_cookie_field() {
        let options = CsrfOptions::new(secret()).cookie_name("__Host-custom");

        assert_eq!(options.cookie_name, "__Host-custom");
    }
}

mod token_length {
    use super::*;

    #[test]
    fn given_custom_length_when_token_length_then_updates_length_field() {
        let options = CsrfOptions::new(secret()).token_length(48);

        assert_eq!(options.token_length, 48);
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_cookie_without_secure_prefix_when_validate_then_returns_prefix_error() {
        let options = CsrfOptions::new(secret()).cookie_name("csrf-token");

        let error = options
            .validate()
            .expect_err("expected invalid cookie prefix error");

        assert_eq!(error, CsrfOptionsError::InvalidCookiePrefix);
    }

    #[test]
    fn given_token_length_below_minimum_when_validate_then_returns_length_error() {
        let options = CsrfOptions::new(secret()).token_length(10);

        let error = options
            .validate()
            .expect_err("expected invalid token length error");

        assert_eq!(
            error,
            CsrfOptionsError::InvalidTokenLength {
                requested: 10,
                minimum: 32,
                maximum: 64,
            }
        );
    }

    #[test]
    fn given_token_length_above_maximum_when_validate_then_returns_length_error() {
        let options = CsrfOptions::new(secret()).token_length(80);

        let error = options
            .validate()
            .expect_err("expected invalid token length error");

        assert_eq!(
            error,
            CsrfOptionsError::InvalidTokenLength {
                requested: 80,
                minimum: 32,
                maximum: 64,
            }
        );
    }

    #[test]
    fn given_valid_configuration_when_validate_then_returns_ok() {
        let options = CsrfOptions::new(secret())
            .cookie_name("__Host-guard")
            .token_length(40);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
