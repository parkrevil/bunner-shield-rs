use super::*;
use crate::executor::FeatureExecutor;
use crate::fetch_metadata::{FetchMetadataOptionsError, FetchMetadataRule};
use crate::normalized_headers::NormalizedHeaders;
use crate::tests_common as common;

fn executor_with(options: FetchMetadataOptions) -> FetchMetadata {
    FetchMetadata::new(options)
}

fn headers(entries: &[(&str, &str)]) -> NormalizedHeaders {
    common::normalized_headers_from(entries)
}

mod validate_options {
    use super::*;

    #[test]
    fn given_default_options_when_validate_then_ok() {
        let executor = executor_with(FetchMetadataOptions::new());

        assert!(executor.validate_options().is_ok());
    }

    #[test]
    fn given_navigation_enabled_without_destinations_when_validate_then_error() {
        let options = FetchMetadataOptions::new().navigation_destinations([]);
        let executor = executor_with(options);

        let error = executor
            .validate_options()
            .expect_err("expected missing destination error");

        assert_eq!(
            error.to_string(),
            FetchMetadataOptionsError::EmptyNavigationDestinations.to_string()
        );
    }
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_configuration() {
        let options = FetchMetadataOptions::new()
            .allow_legacy_clients(false)
            .allow_cross_site_rule(FetchMetadataRule::new().mode(FetchMode::Cors));
        let executor = executor_with(options.clone());

        let result = executor.options();

        assert_eq!(result, &options);
    }
}

mod execute {
    use super::*;

    mod success {
        use super::*;

        #[test]
        fn given_same_site_request_when_execute_then_allows() {
            let mut headers = headers(&[("Sec-Fetch-Site", "same-site")]);

            assert!(executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .is_ok());
        }

        #[test]
        fn given_missing_headers_and_legacy_allowed_when_execute_then_allows() {
            let mut headers = headers(&[]);

            assert!(executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .is_ok());
        }

        #[test]
        fn given_cross_site_navigation_with_user_activation_when_execute_then_allows() {
            let mut headers = headers(&[
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Dest", "document"),
                ("Sec-Fetch-User", "?1"),
            ]);

            assert!(executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .is_ok());
        }

        #[test]
        fn given_cross_site_cors_request_with_explicit_allow_rule_when_execute_then_allows() {
            let options = FetchMetadataOptions::new()
                .allow_cross_site_rule(FetchMetadataRule::new().mode(FetchMode::Cors));
            let mut headers = headers(&[
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "cors"),
                ("Sec-Fetch-Dest", "empty"),
            ]);

            assert!(executor_with(options).execute(&mut headers).is_ok());
        }
    }

    mod failure {
        use super::*;

        #[test]
        fn given_missing_headers_and_legacy_disallowed_when_execute_then_fails() {
            let mut headers = headers(&[]);
            let options = FetchMetadataOptions::new().allow_legacy_clients(false);

            let error = executor_with(options)
                .execute(&mut headers)
                .expect_err("expected legacy rejection error");

            assert_eq!(error.to_string(), FetchMetadataError::MissingHeaders.to_string());
        }

        #[test]
        fn given_cross_site_navigation_without_user_activation_when_execute_then_blocks() {
            let mut headers = headers(&[
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Dest", "document"),
            ]);

            let error = executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .expect_err("expected navigation block");

            assert!(error.to_string().contains("cross-site request blocked"));
        }

        #[test]
        fn given_cross_site_request_without_allowance_when_execute_then_blocks() {
            let mut headers = headers(&[
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "cors"),
                ("Sec-Fetch-Dest", "empty"),
            ]);

            let error = executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .expect_err("expected cross-site block");

            assert!(error.to_string().contains("cross-site request blocked"));
        }

        #[test]
        fn given_missing_destination_header_when_execute_then_returns_error() {
            let mut headers = headers(&[
                ("Sec-Fetch-Site", "cross-site"),
                ("Sec-Fetch-Mode", "navigate"),
            ]);

            let error = executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .expect_err("expected missing destination error");

            assert!(error.to_string().contains("required fetch metadata header `Sec-Fetch-Dest` missing"));
        }

        #[test]
        fn given_invalid_site_header_when_execute_then_returns_error() {
            let mut headers = headers(&[("Sec-Fetch-Site", " ")]);

            let error = executor_with(FetchMetadataOptions::new())
                .execute(&mut headers)
                .expect_err("expected invalid site rejection");

            assert!(
                error
                    .to_string()
                    .contains("invalid value ` ` for header `Sec-Fetch-Site`")
            );
        }
    }
}
