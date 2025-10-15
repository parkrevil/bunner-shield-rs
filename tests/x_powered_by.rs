use bunner_shield_rs::Shield;
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
