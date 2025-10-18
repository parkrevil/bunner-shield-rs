use super::*;
use crate::XFrameOptionsPolicy;
use crate::tests_common as common;

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);
        let executor = XFrameOptions::new(options);

        let result = executor.options();

        let expected = XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_x_frame_options_header() {
        let executor = XFrameOptions::new(XFrameOptionsOptions::new());
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(result.get("X-Frame-Options"), Some(&"DENY".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor =
            XFrameOptions::new(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin));
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
            first.get("X-Frame-Options"),
            Some(&"SAMEORIGIN".to_string())
        );
        assert_eq!(
            second.get("X-Frame-Options"),
            Some(&"SAMEORIGIN".to_string())
        );
    }
}
