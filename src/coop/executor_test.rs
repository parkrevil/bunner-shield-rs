use super::*;
use crate::CoopPolicy;
use crate::tests_common as common;

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = CoopOptions::new().policy(CoopPolicy::UnsafeNone);
        let executor = Coop::new(options);

        let result = executor.options();

        let expected = CoopOptions::new().policy(CoopPolicy::UnsafeNone);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_coop_header_with_cached_value() {
        let executor = Coop::new(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups));
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin-allow-popups".to_string())
        );
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_same_header_value() {
        let executor = Coop::new(CoopOptions::new().policy(CoopPolicy::UnsafeNone));
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
            first.get("Cross-Origin-Opener-Policy"),
            Some(&"unsafe-none".to_string())
        );
        assert_eq!(
            second.get("Cross-Origin-Opener-Policy"),
            Some(&"unsafe-none".to_string())
        );
    }
}
