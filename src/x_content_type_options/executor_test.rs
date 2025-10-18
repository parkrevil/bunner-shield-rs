use super::*;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod validation {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = XContentTypeOptions::new();

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_x_content_type_options_header() {
        let executor = XContentTypeOptions::new();
        let mut headers = common::normalized_headers_from(&[("Content-Type", "text/html")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
        assert_eq!(result.get("Content-Type"), Some(&"text/html".to_string()));
    }

    #[test]
    fn given_existing_header_when_execute_then_overwrites_previous_value() {
        let executor = XContentTypeOptions::new();
        let mut headers =
            common::normalized_headers_from(&[("X-Content-Type-Options", "disabled")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("X-Content-Type-Options"),
            Some(&"nosniff".to_string())
        );
    }
}
