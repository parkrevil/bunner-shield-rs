use super::{NormalizedHeaders, is_multi_value, split_multi_values};
use crate::tests_common as common;
use std::borrow::Cow;

mod new {
    use super::*;

    #[test]
    fn given_mixed_case_headers_when_new_then_allows_case_insensitive_lookup() {
        let headers = NormalizedHeaders::new(common::headers_with(&[("X-Test", "value")]));

        let values = headers.get_all("x-test").expect("values");

        assert_eq!(values, &[Cow::Borrowed("value")]);
    }

    #[test]
    fn given_huge_header_value_when_new_then_preserves_entire_payload() {
        let large_value = "a".repeat(12_288);
        let headers =
            NormalizedHeaders::new(common::headers_with(&[("X-Large", large_value.as_str())]));

        let values = headers.get_all("x-large").expect("values");

        assert_eq!(values.len(), 1);
        assert_eq!(values[0], large_value.as_str());
    }

    #[test]
    fn given_unicode_header_value_when_new_then_preserves_multilingual_text() {
        let headers = NormalizedHeaders::new(common::headers_with(&[("Emoji", "한글😊中文🚀")]));

        let values = headers.get_all("emoji").expect("values");

        assert_eq!(values, &[Cow::Borrowed("한글😊中文🚀")]);
    }

    #[test]
    fn given_special_character_header_when_new_then_retains_original_value() {
        let headers = NormalizedHeaders::new(common::headers_with(&[(
            "X-Feature_!@#$%^&*()",
            "Token=\"Value\"; Path=/; Secure; HttpOnly",
        )]));

        let values = headers
            .get_all("x-feature_!#$%^&*")
            .expect("values after sanitizing header name");

        assert_eq!(
            values,
            &[Cow::Borrowed("Token=\"Value\"; Path=/; Secure; HttpOnly")]
        );

        let result = headers.into_result();
        assert_eq!(
            result.get("X-Feature_!#$%^&*").expect("sanitized header"),
            "Token=\"Value\"; Path=/; Secure; HttpOnly"
        );
    }

    #[test]
    fn given_control_characters_when_new_then_sanitizes_value() {
        let headers = NormalizedHeaders::new(common::headers_with(&[(
            "Permissions-Policy",
            "camera=()\r\ngeolocation=()",
        )]));

        let values = headers.get_all("permissions-policy").expect("values");

        assert_eq!(values, &[Cow::Borrowed("camera=() geolocation=()")]);
    }

    #[test]
    fn given_header_name_with_control_characters_when_new_then_sanitizes_name() {
        let headers =
            NormalizedHeaders::new(common::headers_with(&[("X-Test\r\nSet-Cookie", "value")]));

        let values = headers.get_all("x-testset-cookie").expect("values");

        assert_eq!(values, &[Cow::Borrowed("value")]);
    }

    #[test]
    fn given_unrecoverable_header_name_when_new_then_drops_entry() {
        let result = NormalizedHeaders::new(common::headers_with(&[("\r\n", "value")]));

        assert!(result.into_result().is_empty());
    }
}

mod insert {
    use super::*;

    #[test]
    fn given_existing_header_when_insert_then_overwrites_single_value_entries() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[("x-test", "old")]));

        headers.insert("X-Test", "new");

        let values = headers.get_all("x-test").expect("values");
        assert_eq!(values, &[Cow::Borrowed("new")]);
    }

    #[test]
    fn given_multi_value_header_when_insert_then_appends_split_values() {
        let mut headers =
            NormalizedHeaders::new(common::headers_with(&[("Set-Cookie", "session=one")]));

        headers.insert("set-cookie", "token=two\nSet-Cookie: theme=dark");

        let values = headers.get_all("Set-Cookie").expect("values");
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], "session=one");
        assert_eq!(values[1], "token=two");
        assert_eq!(values[2], "theme=dark");
    }

    #[test]
    fn given_special_character_value_when_insert_then_stores_literal_text() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));
        let value = "token=\"abc123\"; path=/; secure; httponly; version=1";

        headers.insert("Set-Cookie", value);

        let values = headers.get_all("set-cookie").expect("values");
        assert_eq!(values, &[Cow::Borrowed(value)]);
    }

    #[test]
    fn given_control_characters_when_insert_then_sanitizes_value() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));

        headers.insert("X-Test", "one\r\ntwo\u{0008}three");

        let values = headers.get_all("x-test").expect("values");
        assert_eq!(values, &[Cow::Borrowed("one two three")]);
    }

    #[test]
    fn given_header_name_with_control_characters_when_insert_then_sanitizes_name() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));

        headers.insert("X-Bad\r\nHeader", "value");

        let values = headers.get_all("x-badheader").expect("values");
        assert_eq!(values, &[Cow::Borrowed("value")]);
    }

    #[test]
    fn given_unrecoverable_header_name_when_insert_then_ignores_entry() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));

        headers.insert("\r\n", "value");

        assert!(headers.into_result().is_empty());
    }
}

mod insert_owned {
    use super::*;

    #[test]
    fn given_owned_value_when_insert_owned_then_inserts_into_store() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));

        headers.insert_owned("X-Test", "value".to_string());

        let values = headers.get_all("x-test").expect("values");
        assert_eq!(values, &[Cow::Borrowed("value")]);
    }
}

mod remove {
    use super::*;

    #[test]
    fn given_existing_header_when_remove_then_removes_case_insensitively() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[("X-Test", "value")]));

        headers.remove("x-test");

        assert!(headers.get_all("X-Test").is_none());
    }

    #[test]
    fn given_mixed_case_name_when_remove_then_removes_entry() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[("X-CuStOm", "present")]));

        headers.remove("x-custom");

        assert!(headers.get_all("X-Custom").is_none());
    }

    #[test]
    fn given_name_with_internal_whitespace_when_remove_then_removes_entry() {
        let mut headers =
            NormalizedHeaders::new(common::headers_with(&[("X Custom Header", "value")]));

        headers.remove("x custom header");

        assert!(headers.get_all("X Custom Header").is_none());
    }
}

mod get_all {
    use super::*;

    #[test]
    fn given_missing_header_when_get_all_then_returns_none() {
        let headers = NormalizedHeaders::new(common::headers_with(&[]));

        assert!(headers.get_all("missing").is_none());
    }

    #[test]
    fn given_many_case_variations_when_get_all_then_collates_all_matches() {
        let mut headers = NormalizedHeaders::new(common::headers_with(&[]));
        for index in 0..120 {
            let name = if index % 2 == 0 {
                format!("X-Custom-{index}")
            } else {
                format!("x-CUSTOM-{index}")
            };
            headers.insert_owned(&name, format!("value-{index}"));
        }

        let mut found_count = 0;
        for index in 0..120 {
            let key = format!("x-custom-{index}");
            if headers.get_all(&key).is_some() {
                found_count += 1;
            }
        }

        assert_eq!(found_count, 120);
    }
}

mod into_result {
    use super::*;

    #[test]
    fn given_headers_when_into_result_then_returns_original_names() {
        let headers = NormalizedHeaders::new(common::headers_with(&[("X-Test", "value")]));

        let result = headers.into_result();

        assert_eq!(result.get("X-Test").map(String::as_str), Some("value"));
    }
}

mod is_multi_value {
    use super::*;

    #[test]
    fn given_header_name_when_is_multi_value_then_matches_set_cookie_only() {
        assert!(is_multi_value("set-cookie"));
        assert!(!is_multi_value("x-test"));
    }
}

mod split_multi_values {
    use super::*;

    #[test]
    fn given_raw_value_when_split_multi_values_then_splits_and_strips_markers() {
        let values = split_multi_values("session=one\n\nSet-Cookie: token=two\n \n".to_string());

        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "session=one");
        assert_eq!(values[1], "token=two");
    }

    #[test]
    fn given_windows_line_endings_when_split_multi_values_then_ignores_carriage_returns() {
        let values = split_multi_values(
            "session=alpha\r\nSet-Cookie: beta=two\r\n\r\nSet-Cookie: gamma=three".to_string(),
        );

        let tokens: Vec<&str> = values.iter().map(|value| value.as_ref()).collect();
        assert_eq!(tokens, vec!["session=alpha", "beta=two", "gamma=three"]);
    }

    #[test]
    fn given_prefixed_segment_when_split_multi_values_then_trims_marker_only_once() {
        let values = split_multi_values(
            "Set-Cookie: session=one; Path=/\n  Set-Cookie: theme=dark; Secure".to_string(),
        );

        let tokens: Vec<&str> = values.iter().map(|value| value.as_ref()).collect();
        assert_eq!(tokens, vec!["session=one; Path=/", "theme=dark; Secure"]);
    }
}
