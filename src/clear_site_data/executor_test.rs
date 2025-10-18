use super::*;
use crate::clear_site_data::ClearSiteDataOptionsError;
use crate::tests_common as common;

mod validate_options {
    use super::*;
    use crate::executor::FeatureExecutor;

    #[test]
    fn given_selected_section_when_validate_options_then_returns_ok() {
        let executor = ClearSiteData::new(ClearSiteDataOptions::new().cache());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }

    #[test]
    fn given_no_section_selected_when_validate_options_then_returns_error() {
        let executor = ClearSiteData::new(ClearSiteDataOptions::new());

        let error = executor
            .validate_options()
            .expect_err("expected validation failure");

        assert_eq!(
            error.to_string(),
            ClearSiteDataOptionsError::NoSectionsSelected.to_string()
        );
    }
}

mod options {
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

    #[test]
    fn given_executor_when_execute_multiple_times_then_reuses_cached_header_value() {
        let executor = ClearSiteData::new(ClearSiteDataOptions::new().cache().storage());
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
            first.get("Clear-Site-Data"),
            Some(&"\"cache\", \"storage\"".to_string())
        );
        assert_eq!(
            second.get("Clear-Site-Data"),
            Some(&"\"cache\", \"storage\"".to_string())
        );
    }
}
