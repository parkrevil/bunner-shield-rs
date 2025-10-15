use bunner_shield_rs::{
    ClearSiteDataOptions, ClearSiteDataOptionsError, Shield, ShieldError, header_keys,
    header_values,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_header(key: &str, value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(key.to_string(), value.to_string());
    headers
}

mod success {
    use super::*;

    #[test]
    fn given_cache_section_when_secure_then_sets_cache_directive() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().cache())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get(header_keys::CLEAR_SITE_DATA).map(String::as_str),
            Some(header_values::CLEAR_SITE_DATA_CACHE)
        );
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

        let expected = [
            header_values::CLEAR_SITE_DATA_CACHE,
            header_values::CLEAR_SITE_DATA_COOKIES,
            header_values::CLEAR_SITE_DATA_STORAGE,
            header_values::CLEAR_SITE_DATA_EXECUTION_CONTEXTS,
        ]
        .join(", ");

        assert_eq!(
            result.get(header_keys::CLEAR_SITE_DATA).map(String::as_str),
            Some(expected.as_str())
        );
    }

    #[test]
    fn given_existing_directive_header_when_secure_then_overwrites_with_computed_value() {
        let shield = Shield::new()
            .clear_site_data(ClearSiteDataOptions::new().storage())
            .expect("feature");

        let result = shield
            .secure(with_header(
                header_keys::CLEAR_SITE_DATA,
                header_values::CLEAR_SITE_DATA_COOKIES,
            ))
            .expect("secure");

        assert_eq!(
            result.get(header_keys::CLEAR_SITE_DATA).map(String::as_str),
            Some(header_values::CLEAR_SITE_DATA_STORAGE)
        );
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
        assert_eq!(
            result.get(header_keys::CLEAR_SITE_DATA).map(String::as_str),
            Some(header_values::CLEAR_SITE_DATA_COOKIES)
        );
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
