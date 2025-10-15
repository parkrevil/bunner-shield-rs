use bunner_shield_rs::{
    SameSiteOptions, SameSiteOptionsError, SameSitePolicy, Shield, ShieldError,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_cookie(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Set-Cookie".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_cookie_without_attributes_when_secure_then_sets_defaults() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let result = shield.secure(with_cookie("session=abc")).expect("secure");

        assert_eq!(
            result.get("Set-Cookie").map(String::as_str),
            Some("session=abc; Secure; HttpOnly; SameSite=Lax")
        );
    }

    #[test]
    fn given_cookie_with_attributes_when_secure_then_overrides_policy_flags() {
        let options = SameSiteOptions::new()
            .http_only(false)
            .same_site(SameSitePolicy::Strict);
        let shield = Shield::new().same_site(options).expect("feature");

        let result = shield
            .secure(with_cookie("session=abc; SameSite=None; Secure"))
            .expect("secure");

        assert_eq!(
            result.get("Set-Cookie").map(String::as_str),
            Some("session=abc; Secure; SameSite=Strict")
        );
    }

    #[test]
    fn given_request_without_cookie_when_secure_then_leaves_headers_untouched() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert!(result.is_empty());
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_cookie_with_custom_attributes_when_secure_then_preserves_unrelated_pairs() {
        let shield = Shield::new()
            .same_site(SameSiteOptions::new())
            .expect("feature");

        let mut headers = with_cookie("session=abc; Path=/; Domain=example.com");
        headers.insert("X-Other".to_string(), "value".to_string());

        let result = shield.secure(headers).expect("secure");

        let cookie = result.get("Set-Cookie").expect("cookie present");
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Domain=example.com"));
        assert!(cookie.contains("SameSite=Lax"));
        assert_eq!(result.get("X-Other").map(String::as_str), Some("value"));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> SameSiteOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<SameSiteOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_none_without_secure_when_add_feature_then_returns_validation_error() {
        let options = SameSiteOptions::new()
            .secure(false)
            .same_site(SameSitePolicy::None);

        let error = expect_validation_error(Shield::new().same_site(options));

        assert!(matches!(
            error,
            SameSiteOptionsError::SameSiteNoneRequiresSecure
        ));
    }
}
