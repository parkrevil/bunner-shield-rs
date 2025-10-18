use super::*;

mod new {
    use super::*;

    #[test]
    fn given_no_args_when_new_then_creates_empty_options() {
        let options = ClearSiteDataOptions::new();

        let value = options.header_value();

        assert!(value.is_empty());
    }
}

mod execution_contexts {
    use super::*;

    #[test]
    fn given_new_options_when_execution_contexts_then_enables_section() {
        let options = ClearSiteDataOptions::new().execution_contexts();

        let value = options.header_value();

        assert_eq!(value, "\"executionContexts\"");
    }

    #[test]
    fn given_other_sections_when_execution_contexts_then_adds_to_list() {
        let options = ClearSiteDataOptions::new()
            .cache()
            .execution_contexts();

        let value = options.header_value();

        assert!(value.contains("\"cache\""));
        assert!(value.contains("\"executionContexts\""));
    }
}

mod cache {
    use super::*;

    #[test]
    fn given_new_options_when_cache_then_enables_cache_section() {
        let options = ClearSiteDataOptions::new().cache();

        let value = options.header_value();

        assert_eq!(value, "\"cache\"");
    }
}

mod cookies {
    use super::*;

    #[test]
    fn given_new_options_when_cookies_then_enables_cookies_section() {
        let options = ClearSiteDataOptions::new().cookies();

        let value = options.header_value();

        assert_eq!(value, "\"cookies\"");
    }
}

mod storage {
    use super::*;

    #[test]
    fn given_new_options_when_storage_then_enables_storage_section() {
        let options = ClearSiteDataOptions::new().storage();

        let value = options.header_value();

        assert_eq!(value, "\"storage\"");
    }
}

mod header_value {
    use super::*;

    #[test]
    fn given_selected_sections_when_header_value_then_returns_joined_tokens() {
        let options = ClearSiteDataOptions::new().cache().cookies().storage();

        let value = options.header_value();

        assert_eq!(value, "\"cache\", \"cookies\", \"storage\"");
    }

    #[test]
    fn given_no_sections_when_header_value_then_returns_empty_string() {
        let options = ClearSiteDataOptions::new();

        let value = options.header_value();

        assert!(value.is_empty());
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_selection_present_when_validate_then_returns_ok() {
        let options = ClearSiteDataOptions::new().cookies();

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_no_selection_when_validate_then_returns_no_sections_error() {
        let options = ClearSiteDataOptions::new();

        let result = options.validate();

        let error = result.expect_err("expected validation failure");
        assert_eq!(error, ClearSiteDataOptionsError::NoSectionsSelected);
    }
}
