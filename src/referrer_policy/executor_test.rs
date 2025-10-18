use super::*;
use crate::executor::FeatureExecutor;
use crate::ReferrerPolicyValue;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_executor_when_validate_options_then_returns_ok() {
        let executor = ReferrerPolicy::new(ReferrerPolicyOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_cached_options() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::Origin);
        let executor = ReferrerPolicy::new(options);

        let result = executor.options();

        let expected = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::Origin);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_referrer_policy_header() {
        let executor = ReferrerPolicy::new(
            ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::NoReferrer),
        );
        let mut headers = common::normalized_headers_from(&[("X-Other", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Referrer-Policy"),
            Some(&"no-referrer".to_string())
        );
        assert_eq!(result.get("X-Other"), Some(&"1".to_string()));
    }

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = ReferrerPolicy::new(
            ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::StrictOrigin),
        );
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
            first.get("Referrer-Policy"),
            Some(&"strict-origin".to_string())
        );
        assert_eq!(
            second.get("Referrer-Policy"),
            Some(&"strict-origin".to_string())
        );
    }
}
