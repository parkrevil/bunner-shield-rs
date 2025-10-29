use super::*;
use crate::CspNonceManager;
use crate::CspSource;
use crate::tests_common as common;

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = CspOptions::new().default_src([CspSource::SelfKeyword]);
        let executor = Csp::new(options);

        let result = executor.options();

        let expected = CspOptions::new().default_src([CspSource::SelfKeyword]);
        assert_eq!(result.directives, expected.directives);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_content_security_policy_header() {
        let executor = Csp::new(
            CspOptions::new()
                .default_src([CspSource::SelfKeyword])
                .script_src(|script| script.sources([CspSource::StrictDynamic])),
        );
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        let value = result
            .get("Content-Security-Policy")
            .expect("expected csp header");
        assert!(value.contains("default-src 'self'"));
        assert!(value.contains("script-src 'strict-dynamic'"));
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = Csp::new(CspOptions::new().default_src([CspSource::Wildcard]));
        let mut first_headers = common::normalized_headers_from(&[]);
        let mut second_headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut first_headers)
            .expect("first execute should succeed");
        executor
            .execute(&mut second_headers)
            .expect("second execute should succeed");

        let first = first_headers.into_result();
        let second = second_headers.into_result();
        assert_eq!(
            first.get("Content-Security-Policy"),
            Some(&"default-src *".to_string())
        );
        assert_eq!(
            second.get("Content-Security-Policy"),
            Some(&"default-src *".to_string())
        );
    }

    #[test]
    fn given_runtime_nonce_configuration_when_execute_then_emits_unique_nonce_per_request() {
        let options = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::with_size(16).expect("nonce size"))
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| script.runtime_nonce().strict_dynamic());
        let executor = Csp::new(options);
        let mut first_headers = common::normalized_headers_from(&[]);
        let mut second_headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut first_headers)
            .expect("first execute should succeed");
        executor
            .execute(&mut second_headers)
            .expect("second execute should succeed");

        let first = first_headers.into_result();
        let second = second_headers.into_result();
        let first_value = first
            .get("Content-Security-Policy")
            .expect("expected csp header on first execution");
        let second_value = second
            .get("Content-Security-Policy")
            .expect("expected csp header on second execution");

        assert!(first_value.contains("'nonce-"));
        assert!(second_value.contains("'nonce-"));
        assert!(first_value.contains("'strict-dynamic'"));
        assert!(second_value.contains("'strict-dynamic'"));
        assert_ne!(first_value, second_value, "nonce should differ per request");
    }

    #[test]
    fn given_report_only_when_execute_then_sets_report_only_header() {
        let executor = Csp::new(
            CspOptions::new()
                .report_only()
                .default_src([CspSource::SelfKeyword]),
        );
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert!(
            result.contains_key("Content-Security-Policy-Report-Only"),
            "expected report-only header"
        );
        assert!(!result.contains_key("Content-Security-Policy"));
        let value = result
            .get("Content-Security-Policy-Report-Only")
            .expect("expected report-only header");
        assert!(value.contains("default-src 'self'"));
    }

    #[test]
    fn given_report_only_runtime_nonce_configuration_when_execute_then_uses_report_only_header() {
        let options = CspOptions::new()
            .report_only()
            .runtime_nonce_manager(CspNonceManager::with_size(16).expect("nonce size"))
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| script.runtime_nonce().strict_dynamic());
        let executor = Csp::new(options);
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        let value = result
            .get("Content-Security-Policy-Report-Only")
            .expect("expected report-only header");
        assert!(value.contains("'nonce-"), "nonce should be present");
        assert!(value.contains("'strict-dynamic'"));
        assert!(!result.contains_key("Content-Security-Policy"));
    }
}
