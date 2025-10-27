use bunner_shield_rs::{
    FetchMetadataError, FetchMetadataOptions, FetchMetadataOptionsError, FetchMetadataRule,
    FetchMode, Shield, ShieldError,
};
mod common;
use common::{empty_headers, headers_with};
use std::collections::HashMap;

fn cross_site_navigation_headers() -> HashMap<String, String> {
    headers_with(&[
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-User", "?1"),
    ])
}

fn cross_site_cors_headers() -> HashMap<String, String> {
    headers_with(&[
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Dest", "empty"),
    ])
}

fn same_site_headers() -> HashMap<String, String> {
    headers_with(&[("Sec-Fetch-Site", "same-site")])
}

mod success {
    use super::*;

    #[test]
    fn given_same_site_request_when_secure_then_returns_headers_unchanged() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");
        let headers = same_site_headers();

        let result = shield
            .secure(headers.clone())
            .expect("same-site request should pass");

        assert_eq!(result, headers);
    }

    #[test]
    fn given_cross_site_navigation_with_user_activation_when_secure_then_allows_request() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");
        let headers = cross_site_navigation_headers();

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result, headers);
    }

    #[test]
    fn given_cross_site_cors_request_with_allow_rule_when_secure_then_allows_request() {
        let options = FetchMetadataOptions::new()
            .allow_cross_site_rule(FetchMetadataRule::new().mode(FetchMode::Cors));
        let shield = Shield::new().fetch_metadata(options).expect("feature");
        let headers = cross_site_cors_headers();

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result, headers);
    }

    #[test]
    fn given_missing_fetch_metadata_headers_and_legacy_allowed_when_secure_then_allows() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");

        let result = shield
            .secure(empty_headers())
            .expect("legacy clients should pass");

        assert!(result.is_empty());
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_headers_with_mixed_case_keys_when_secure_then_handles_case_insensitively() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");
        let headers = headers_with(&[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-user", "?1"),
        ]);

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result, headers);
    }

    #[test]
    fn given_request_with_unrelated_headers_when_secure_then_preserves_existing_entries() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");
        let mut headers = cross_site_navigation_headers();
        headers.insert("X-App".to_string(), "api".to_string());

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result.get("X-App"), Some(&"api".to_string()));
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> FetchMetadataOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<FetchMetadataOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    fn expect_execution_error(
        result: Result<HashMap<String, String>, ShieldError>,
    ) -> FetchMetadataError {
        match result {
            Err(ShieldError::ExecutionFailed(err)) => err
                .downcast::<FetchMetadataError>()
                .map(|boxed| *boxed)
                .unwrap_or_else(|err| panic!("unexpected error type: {err}")),
            Err(ShieldError::ExecutorValidationFailed(err)) => {
                panic!("expected execution failure, got validation error: {err}")
            }
            Ok(_) => panic!("expected execution failure but request succeeded"),
        }
    }

    #[test]
    fn given_navigation_enabled_without_destinations_when_add_feature_then_returns_validation_error()
     {
        let error = expect_validation_error(
            Shield::new().fetch_metadata(FetchMetadataOptions::new().navigation_destinations([])),
        );

        assert_eq!(
            error,
            FetchMetadataOptionsError::EmptyNavigationDestinations
        );
    }

    #[test]
    fn given_cross_site_request_without_allowance_when_secure_then_blocks_request() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");

        let error = expect_execution_error(shield.secure(cross_site_cors_headers()));

        assert!(matches!(error, FetchMetadataError::CrossSiteBlocked { .. }));
    }

    #[test]
    fn given_cross_site_navigation_without_user_activation_when_secure_then_blocks_request() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new())
            .expect("feature");
        let headers = headers_with(&[
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ]);

        let error = expect_execution_error(shield.secure(headers));

        assert!(matches!(error, FetchMetadataError::CrossSiteBlocked { .. }));
    }

    #[test]
    fn given_missing_fetch_metadata_headers_when_secure_and_legacy_disabled_then_blocks() {
        let shield = Shield::new()
            .fetch_metadata(FetchMetadataOptions::new().allow_legacy_clients(false))
            .expect("feature");

        let error = expect_execution_error(shield.secure(empty_headers()));

        assert!(matches!(error, FetchMetadataError::MissingHeaders));
    }
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,32}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();
        prop::collection::vec((name, value), 0..8)
    }

    proptest! {
        #[test]
        fn arbitrary_headers_never_panic(entries in header_entries_strategy()) {
            let shield = Shield::new()
                .fetch_metadata(FetchMetadataOptions::new())
                .expect("feature");
            let mut headers = HashMap::new();
            for (key, value) in entries {
                headers.insert(key, value);
            }

            let _ = shield.secure(headers);
        }
    }
}
