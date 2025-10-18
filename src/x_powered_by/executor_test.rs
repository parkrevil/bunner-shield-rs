use super::*;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = XPoweredBy::new();

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_with_x_powered_by_when_execute_then_removes_header() {
        let executor = XPoweredBy::new();
        let mut headers =
            common::normalized_headers_from(&[("X-Powered-By", "Express"), ("X-Other", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert!(!result.contains_key("X-Powered-By"));
        assert_eq!(result.get("X-Other"), Some(&"1".to_string()));
    }

    #[test]
    fn given_headers_without_x_powered_by_when_execute_then_succeeds_without_changes() {
        let executor = XPoweredBy::new();
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert!(result.is_empty());
    }
}
