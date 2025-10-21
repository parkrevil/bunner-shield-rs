use bunner_shield_rs::Shield;
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_header(key: &str, value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert(key.to_string(), value.to_string());
    headers
}

mod proptests {
    use super::*;
    use std::collections::HashMap;

    fn header_name_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,48}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("X-Powered-By") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn x_powered_by_case_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, "X-Powered-By".len()).prop_map(|mask| {
            "X-Powered-By"
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
        fn given_any_case_variant_when_secure_then_removes_header(
            baseline in header_name_strategy(),
            x_powered_by_name in x_powered_by_case_strategy(),
            x_powered_by_value in header_value_strategy()
        ) {
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            headers.insert(x_powered_by_name, x_powered_by_value);

            let shield = Shield::new().x_powered_by().expect("feature");
            let result = shield.secure(headers).expect("secure");

            let expected = baseline
                .into_iter()
                .collect::<HashMap<String, String>>();

            prop_assert_eq!(result, expected);
        }
    }
}

mod success {
    use super::*;

    #[test]
    fn given_standard_header_when_secure_then_removes_x_powered_by() {
        let mut headers = with_header("X-Powered-By", "Express");
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let shield = Shield::new().x_powered_by().expect("feature");

        let result = shield.secure(headers).expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
        assert_eq!(
            result.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn given_mixed_case_header_when_secure_then_removes_normalized_key() {
        let shield = Shield::new().x_powered_by().expect("feature");

        let result = shield
            .secure(with_header("x-PoWeReD-bY", "Express"))
            .expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
    }

    #[test]
    fn given_lowercase_header_when_secure_then_removes_canonical_key() {
        let shield = Shield::new().x_powered_by().expect("feature");

        let result = shield
            .secure(with_header("x-powered-by", "Express"))
            .expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
        assert!(!result.contains_key("x-powered-by"));
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_absent_header_when_secure_then_leaves_headers_unchanged() {
        let mut headers = empty_headers();
        headers.insert("Server".to_string(), "nginx".to_string());
        let shield = Shield::new().x_powered_by().expect("feature");

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("Server").map(String::as_str), Some("nginx"));
    }
}
