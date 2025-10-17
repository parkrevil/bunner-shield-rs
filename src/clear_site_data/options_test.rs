use super::*;

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
