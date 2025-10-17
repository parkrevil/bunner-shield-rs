use super::*;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod reexports {
    use super::*;

    #[test]
    fn given_module_reexports_when_execute_then_sets_coep_header() {
        let executor = Coep::new(CoepOptions::new().policy(CoepPolicy::RequireCorp));
        let mut headers = common::normalized_headers_from(&[]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(
            result.get("Cross-Origin-Embedder-Policy"),
            Some(&"require-corp".to_string())
        );
    }
}
