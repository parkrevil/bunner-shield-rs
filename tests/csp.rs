use bunner_shield_rs::{
    CspNonceManager, CspOptions, CspOptionsError, CspSource, Shield, ShieldError, header_keys,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_csp(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(
        header_keys::CONTENT_SECURITY_POLICY.to_string(),
        value.to_string(),
    );
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_minimal_policy_when_secure_then_emits_expected_directives() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .base_uri([CspSource::None])
            .frame_ancestors([CspSource::None]);
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CONTENT_SECURITY_POLICY)
                .map(String::as_str),
            Some("default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        );
    }

    #[test]
    fn given_repeated_sources_when_secure_then_deduplicates_tokens() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .img_src([
                CspSource::SelfKeyword,
                CspSource::SelfKeyword,
                CspSource::SelfKeyword,
            ]);
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result
                .get(header_keys::CONTENT_SECURITY_POLICY)
                .map(String::as_str),
            Some("default-src 'self'; img-src 'self'")
        );
    }

    #[test]
    fn given_nonce_manager_when_secure_then_injects_nonce_into_script_src() {
        let nonce = CspNonceManager::new().issue();
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src_with_nonce(nonce.clone());
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let nonce_value = format!("'nonce-{}'", nonce.into_inner());
        let header = result
            .get(header_keys::CONTENT_SECURITY_POLICY)
            .map(String::to_string)
            .expect("csp header");

        assert!(header.contains("script-src"));
        assert!(header.contains(&nonce_value));
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_new_policy() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield
            .secure(with_csp("default-src 'unsafe-inline'"))
            .expect("secure");

        assert_eq!(
            result
                .get(header_keys::CONTENT_SECURITY_POLICY)
                .map(String::as_str),
            Some("default-src 'self'; style-src 'self'")
        );
    }

    #[test]
    fn given_unrelated_headers_when_secure_then_preserves_them() {
        let options = CspOptions::new().default_src([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let mut headers = with_csp("default-src *");
        headers.insert("X-App-Version".to_string(), "9".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-App-Version").map(String::as_str), Some("9"));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> CspOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<CspOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_missing_directives_when_add_feature_then_returns_missing_directives_error() {
        let error = expect_validation_error(Shield::new().csp(CspOptions::new()));

        assert_eq!(error, CspOptionsError::MissingDirectives);
    }

    #[test]
    fn given_conflicting_none_when_add_feature_then_returns_conflicting_none_error() {
        let options = CspOptions::new().default_src([CspSource::None, CspSource::SelfKeyword]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::ConflictingNoneToken);
    }

    #[test]
    fn given_strict_dynamic_without_nonce_when_add_feature_then_returns_nonce_error() {
        let options = CspOptions::new().script_src([CspSource::StrictDynamic]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::StrictDynamicRequiresNonceOrHash);
    }
}
