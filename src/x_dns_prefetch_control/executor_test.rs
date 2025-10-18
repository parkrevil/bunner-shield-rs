use super::*;
use crate::executor::FeatureExecutor;
use crate::XdnsPrefetchControlPolicy;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = XdnsPrefetchControl::new(XdnsPrefetchControlOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On);
        let executor = XdnsPrefetchControl::new(options);

        let result = executor.options();

        let expected = XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_x_dns_prefetch_control_header() {
        let executor = XdnsPrefetchControl::new(
            XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
        );
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("X-DNS-Prefetch-Control"),
            Some(&"on".to_string())
        );
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = XdnsPrefetchControl::new(XdnsPrefetchControlOptions::new());
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
            first.get("X-DNS-Prefetch-Control"),
            Some(&"off".to_string())
        );
        assert_eq!(
            second.get("X-DNS-Prefetch-Control"),
            Some(&"off".to_string())
        );
    }
}
