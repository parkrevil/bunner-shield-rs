use bunner_shield_rs::{ClearSiteDataOptions, ClearSiteDataOptionsError, Shield, ShieldError};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_header(key: &str, value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(key.to_string(), value.to_string());
    headers
}

fn assert_clear_site_data(actual: &str, expected: &[&str]) {
    let mut actual_tokens: Vec<_> = actual
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    let mut expected_tokens: Vec<_> = expected.to_vec();

    actual_tokens.sort_unstable();
    expected_tokens.sort_unstable();

    assert_eq!(actual_tokens, expected_tokens);
}

mod success {
    use super::*;

    #[test]
    fn given_cache_section_when_secure_then_sets_cache_directive() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().cache())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_clear_site_data(header, &["\"cache\""]);
    }

    #[test]
    fn given_all_sections_when_secure_then_respects_specified_order() {
        let shield = Shield::new()
            .clear_site_data(
                ClearSiteDataOptions::new()
                    .cache()
                    .cookies()
                    .storage()
                    .execution_contexts(),
            )
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_clear_site_data(
            header,
            &[
                "\"cache\"",
                "\"cookies\"",
                "\"storage\"",
                "\"executionContexts\"",
            ],
        );
    }

    #[test]
    fn given_existing_directive_header_when_secure_then_overwrites_with_computed_value() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().storage())
            .expect("feature");

        let result = shield
            .secure(with_header("Clear-Site-Data", "\"cookies\""))
            .expect("secure");

        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_clear_site_data(header, &["\"storage\""]);
    }

    #[test]
    fn given_existing_header_with_lowercase_key_when_secure_then_overwrites_using_canonical_case() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().cache())
            .expect("feature");

        let result = shield
            .secure(with_header("clear-site-data", "\"storage\""))
            .expect("secure");

        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_clear_site_data(header, &["\"cache\""]);
        assert!(!result.contains_key("clear-site-data"));
    }

    #[test]
    fn given_irrelevant_headers_when_secure_then_preserves_other_keys() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().cookies())
            .expect("feature");

        let mut headers = with_header("Content-Type", "application/json");
        headers.insert("X-Correlation-Id".to_string(), "abc-123".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            result.get("X-Correlation-Id").map(String::as_str),
            Some("abc-123")
        );
        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_clear_site_data(header, &["\"cookies\""]);
    }

    #[test]
    fn given_duplicate_sections_when_secure_then_emits_unique_tokens_in_canonical_order() {
        let shield = Shield::new()
            .clear_site_data(
                ClearSiteDataOptions::new()
                    .cookies()
                    .cache()
                    .storage()
                    .cookies()
                    .cache(),
            )
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Clear-Site-Data")
            .expect("clear-site-data header");

        assert_eq!(header, "\"cache\", \"cookies\", \"storage\"");
    }
}

mod failure {
    use super::*;

    #[test]
    fn given_no_sections_when_add_feature_then_returns_validation_error() {
        let result = Shield::new().clear_site_data(ClearSiteDataOptions::new());

        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation error, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation error but feature was accepted"),
        };

        let downcast = err
            .downcast_ref::<ClearSiteDataOptionsError>()
            .expect("clear-site-data error");
        assert_eq!(downcast, &ClearSiteDataOptionsError::NoSectionsSelected);
    }
}
