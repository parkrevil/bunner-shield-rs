use super::Shield;
use crate::csp::CspOptions;

mod new {
    use super::*;

    #[test]
    fn given_built_shield_when_secure_then_returns_normalized_headers() {
        let shield = Shield::new()
            .content_security_policy(
                CspOptions::new()
                    .with_directive("default-src", "'self'")
                    .with_directive("base-uri", "'none'")
                    .with_directive("frame-ancestors", "'none'"),
            )
            .expect("feature");
        let headers = vec![
            ("X-Test".to_string(), "A".to_string()),
            ("X-Trace".to_string(), "123".to_string()),
        ];

        let normalized = shield.secure(headers).expect("secure");

        assert_eq!(normalized.get("x-test"), Some("A"));
        assert_eq!(normalized.get("x-trace"), Some("123"));
    }
}
