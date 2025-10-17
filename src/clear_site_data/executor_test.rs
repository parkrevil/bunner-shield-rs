use super::*;
use crate::tests_common as common;

mod options_access {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_cached_reference() {
        let options = ClearSiteDataOptions::new().cache();
        let executor = ClearSiteData::new(options);

        let result = executor.options();

        let expected = ClearSiteDataOptions::new().cache();
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_when_execute_then_sets_clear_site_data_header() {
        let executor = ClearSiteData::new(ClearSiteDataOptions::new().cookies());
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor.execute(&mut headers).expect("execute");

        let result = headers.into_result();
        assert_eq!(
            result.get("Clear-Site-Data"),
            Some(&"\"cookies\"".to_string())
        );
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
    }
}
