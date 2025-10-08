use super::Shield;

mod new {
    use super::*;

    #[test]
    fn given_default_state_when_secure_then_returns_normalized_headers() {
        let shield = Shield::new();
        let headers = vec![
            ("X-Test".to_string(), "A".to_string()),
            ("X-Trace".to_string(), "123".to_string()),
        ];

        let normalized = shield.secure(headers);

        assert_eq!(normalized.get("x-test"), Some("A"));
        assert_eq!(normalized.get("x-trace"), Some("123"));
    }
}
