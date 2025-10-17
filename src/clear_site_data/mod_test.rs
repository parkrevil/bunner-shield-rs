use super::*;
use crate::executor::FeatureExecutor;
use crate::tests_common as common;

mod reexports {
    use super::*;

    #[test]
    fn given_module_reexports_when_execute_then_applies_header() {
        let executor = ClearSiteData::new(ClearSiteDataOptions::new().cache());
        let mut headers = common::normalized_headers_from(&[]);

        executor.execute(&mut headers).expect("execute");

        let result = headers.into_result();
        assert_eq!(
            result.get("Clear-Site-Data"),
            Some(&"\"cache\"".to_string())
        );
    }
}
