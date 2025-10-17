use super::{is_multi_value, split_multi_values, NormalizedHeaders};
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
}

mod get_all {
    use super::*;

    #[test]
    fn given_missing_header_when_get_all_then_returns_none() {
        let headers = NormalizedHeaders::new(common::headers_with(&[]));

        assert!(headers.get_all("missing").is_none());
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
}
