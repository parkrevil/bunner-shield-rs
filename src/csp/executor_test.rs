use super::*;
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
                .script_src([CspSource::StrictDynamic]),
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
}
