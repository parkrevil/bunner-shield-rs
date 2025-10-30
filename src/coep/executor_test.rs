use super::*;
use crate::CoepPolicy;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = Coep::new(CoepOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_cached_reference() {
        let options = CoepOptions::new().policy(CoepPolicy::Credentialless);
        let executor = Coep::new(options);

        let result = executor.options();

        let expected = CoepOptions::new().policy(CoepPolicy::Credentialless);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_coep_header_to_cached_value() {
        let executor = Coep::new(CoepOptions::new().policy(CoepPolicy::RequireCorp));
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Cross-Origin-Embedder-Policy"),
            Some(&"require-corp".to_string())
        );
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
    }

    #[test]
    fn given_report_only_mode_when_execute_then_sets_report_only_header() {
        let executor = Coep::new(CoepOptions::new().report_only());
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Cross-Origin-Embedder-Policy-Report-Only"),
            Some(&"require-corp".to_string())
        );
        assert!(!result.contains_key("Cross-Origin-Embedder-Policy"));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = Coep::new(CoepOptions::new().policy(CoepPolicy::Credentialless));
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
            first.get("Cross-Origin-Embedder-Policy"),
            Some(&"credentialless".to_string())
        );
        assert_eq!(
            second.get("Cross-Origin-Embedder-Policy"),
            Some(&"credentialless".to_string())
        );
    }
}
