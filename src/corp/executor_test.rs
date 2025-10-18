use super::*;
use crate::CorpPolicy;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = Corp::new(CorpOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = CorpOptions::new().policy(CorpPolicy::SameSite);
        let executor = Corp::new(options);

        let result = executor.options();

        let expected = CorpOptions::new().policy(CorpPolicy::SameSite);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_corp_header_with_cached_value() {
        let executor = Corp::new(CorpOptions::new().policy(CorpPolicy::CrossOrigin));
        let mut headers = common::normalized_headers_from(&[("Another", "value")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Cross-Origin-Resource-Policy"),
            Some(&"cross-origin".to_string())
        );
        assert_eq!(result.get("Another"), Some(&"value".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_same_header_value() {
        let executor = Corp::new(CorpOptions::new().policy(CorpPolicy::SameOrigin));
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
            first.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
        assert_eq!(
            second.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
    }
}
