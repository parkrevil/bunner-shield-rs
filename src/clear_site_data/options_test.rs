use super::{ClearSiteDataOptions, ClearSiteDataOptionsError};

mod header_value {
    use super::ClearSiteDataOptions;

    #[test]
    fn given_cache_and_cookies_when_header_value_then_returns_sections_in_order() {
        let options = ClearSiteDataOptions::new().cache().cookies();

        assert_eq!(options.header_value(), "\"cache\", \"cookies\"");
    }

    #[test]
    fn given_all_sections_when_header_value_then_returns_all_in_order() {
        let options = ClearSiteDataOptions::new()
            .cache()
            .cookies()
            .storage()
            .execution_contexts();

        assert_eq!(
            options.header_value(),
            "\"cache\", \"cookies\", \"storage\", \"executionContexts\""
        );
    }
}

mod validate {
    use super::{ClearSiteDataOptions, ClearSiteDataOptionsError};
    use crate::executor::FeatureOptions;

    #[test]
    fn given_sections_when_validate_then_returns_ok() {
        let options = ClearSiteDataOptions::new().storage();

        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_no_sections_when_validate_then_returns_error() {
        let options = ClearSiteDataOptions::new();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(ClearSiteDataOptionsError::NoSectionsSelected)
        ));
    }
}
