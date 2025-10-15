use bunner_shield_rs::Shield;
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_xcto(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("X-Content-Type-Options".to_string(), value.to_string());
    headers
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
