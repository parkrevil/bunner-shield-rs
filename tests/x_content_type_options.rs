use bunner_shield_rs::Shield;
use proptest::prelude::*;
use std::collections::HashMap;
mod common;
use common::empty_headers;

fn with_xcto(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("X-Content-Type-Options".to_string(), value.to_string());
    headers
}

mod proptests {
    use super::*;
    use std::collections::HashMap;

    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("X-Content-Type-Options") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn xcto_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "X-Content-Type-Options".len()).prop_map(|mask| {
            "X-Content-Type-Options"
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

    proptest! {
        #[test]
        fn given_any_header_set_when_secure_then_sets_nosniff_idempotently(
            baseline in header_entries_strategy(),
            existing in prop::option::of((xcto_case_strategy(), header_value_strategy()))
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }

            if let Some((name, value)) = existing {
                headers.insert(name, value);
            }

            let shield = Shield::new().x_content_type_options().expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let expected = baseline.into_iter().collect::<HashMap<String, String>>();
            let mut expected = expected;
            expected.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

            prop_assert_eq!(once, expected.clone());
            prop_assert_eq!(twice, expected);
        }
    }
}

mod success {
    use super::*;

    #[test]
    fn given_headers_without_nosniff_when_secure_then_sets_header() {
        let shield = Shield::new().x_content_type_options().expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_nosniff() {
        let shield = Shield::new().x_content_type_options().expect("feature");

        let result = shield.secure(with_xcto("whatever")).expect("secure");

        assert_eq!(
            result.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
    }

    #[test]
    fn given_existing_header_with_lowercase_key_when_secure_then_overwrites_case_insensitively() {
        let shield = Shield::new().x_content_type_options().expect("feature");

        let mut headers = empty_headers();
        headers.insert(
            "x-content-type-options".to_string(),
            "deprecated".to_string(),
        );

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
        assert!(!result.contains_key("x-content-type-options"));
    }

    #[test]
    fn given_other_headers_when_secure_then_preserves_them() {
        let shield = Shield::new().x_content_type_options().expect("feature");

        let mut headers = with_xcto("whatever");
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Content-Type").map(String::as_str),
            Some("text/html")
        );
    }
}
