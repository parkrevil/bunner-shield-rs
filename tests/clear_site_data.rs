use bunner_shield_rs::{ClearSiteDataOptions, ClearSiteDataOptionsError, Shield, ShieldError};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

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

mod proptests {
    use super::*;

    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("Clear-Site-Data") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn csd_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "Clear-Site-Data".len()).prop_map(|mask| {
            "Clear-Site-Data"
                .chars()
                .zip(mask)
                .map(|(ch, lower)| match ch {
                    '-' => '-',
                    letter if lower => letter.to_ascii_lowercase(),
                    letter => letter.to_ascii_uppercase(),
                })
                .collect()
        })
    }

    fn header_value_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[ -~]{0,96}").unwrap()
    }

    fn options_for_mask(mask: u8) -> ClearSiteDataOptions {
        let mut opt = ClearSiteDataOptions::new();
        if mask & 0b0001 != 0 {
            opt = opt.cache();
        }
        if mask & 0b0010 != 0 {
            opt = opt.cookies();
        }
        if mask & 0b0100 != 0 {
            opt = opt.storage();
        }
        if mask & 0b1000 != 0 {
            opt = opt.execution_contexts();
        }
        opt
    }

    fn expected_value_for_mask(mask: u8) -> String {
        let mut parts = Vec::new();
        if mask & 0b0001 != 0 {
            parts.push("\"cache\"");
        }
        if mask & 0b0010 != 0 {
            parts.push("\"cookies\"");
        }
        if mask & 0b0100 != 0 {
            parts.push("\"storage\"");
        }
        if mask & 0b1000 != 0 {
            parts.push("\"executionContexts\"");
        }
        parts.join(", ")
    }

    proptest! {
        #[test]
        fn given_any_headers_and_optional_existing_when_secure_then_sets_computed_value_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((csd_case_strategy(), header_value_strategy())),
            // choose non-empty subset of the 4 sections
            mask in 1u8..=15u8,
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            if let Some((name, value)) = existing { headers.insert(name, value); }

            let shield = Shield::new()
                .clear_site_data(options_for_mask(mask))
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("Clear-Site-Data".to_string(), expected_value_for_mask(mask));

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }

    fn two_distinct_csd_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (csd_case_strategy(), csd_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            dup_cases in two_distinct_csd_cases_strategy(),
            values in (header_value_strategy(), header_value_strategy()),
            mask in 1u8..=15u8,
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            // Insert two differently-cased Clear-Site-Data entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let shield = Shield::new()
                .clear_site_data(options_for_mask(mask))
                .expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected = baseline.into_iter().collect::<HashMap<_, _>>();
            expected.insert("Clear-Site-Data".to_string(), expected_value_for_mask(mask));

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}
