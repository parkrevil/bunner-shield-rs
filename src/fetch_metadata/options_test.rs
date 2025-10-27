use super::*;
use crate::executor::FeatureOptions;

mod new {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_sets_navigation_defaults() {
        let options = FetchMetadataOptions::new();

        assert!(options.allow_navigation_requests);
        assert!(options.require_user_activation_for_navigation);
        assert!(options.allow_legacy_clients);
        assert_eq!(
            options.navigation_destinations,
            vec![FetchDestination::Document, FetchDestination::NestedDocument]
        );
        assert!(options.cross_site_allowances.is_empty());
    }
}

mod navigation_destinations {
    use super::*;

    #[test]
    fn given_custom_navigation_destinations_when_set_then_replaces_existing_list() {
        let options = FetchMetadataOptions::new()
            .navigation_destinations([FetchDestination::Empty, FetchDestination::Document]);

        assert_eq!(
            options.navigation_destinations,
            vec![FetchDestination::Empty, FetchDestination::Document]
        );
    }

    #[test]
    fn given_duplicate_destinations_when_added_then_deduplicates_entries() {
        let options = FetchMetadataOptions::new()
            .add_navigation_destination(FetchDestination::Document)
            .add_navigation_destination(FetchDestination::Document)
            .add_navigation_destination(FetchDestination::Empty);

        assert_eq!(
            options.navigation_destinations,
            vec![
                FetchDestination::Document,
                FetchDestination::NestedDocument,
                FetchDestination::Empty
            ]
        );
    }
}

mod cross_site_allowances {
    use super::*;

    #[test]
    fn given_allow_cross_site_rule_when_added_twice_then_keeps_single_entry() {
        let rule = FetchMetadataRule::new().mode(FetchMode::Cors);

        let options = FetchMetadataOptions::new()
            .allow_cross_site_rule(rule.clone())
            .allow_cross_site_rule(rule.clone());

        assert_eq!(options.cross_site_allowances, vec![rule]);
    }

    #[test]
    fn given_multiple_allowances_when_added_then_preserves_insertion_order() {
        let cors = FetchMetadataRule::new().mode(FetchMode::Cors);
        let navigate_document = FetchMetadataRule::new()
            .mode(FetchMode::Navigate)
            .destination(FetchDestination::Document);

        let options = FetchMetadataOptions::new()
            .allow_cross_site_rules([cors.clone(), navigate_document.clone()]);

        assert_eq!(options.cross_site_allowances, vec![cors, navigate_document]);
    }

    #[test]
    fn given_rule_with_mode_and_destination_when_matches_then_requires_both() {
        let rule = FetchMetadataRule::new()
            .mode(FetchMode::Navigate)
            .destination(FetchDestination::Document);

        assert!(rule.matches(
            Some(&FetchMode::Navigate),
            Some(&FetchDestination::Document)
        ));
        assert!(!rule.matches(Some(&FetchMode::Navigate), Some(&FetchDestination::Empty)));
        assert!(!rule.matches(Some(&FetchMode::Cors), Some(&FetchDestination::Document)));
    }
}

mod legacy_clients {
    use super::*;

    #[test]
    fn given_allow_legacy_clients_disabled_when_configured_then_reflects_flag() {
        let options = FetchMetadataOptions::new().allow_legacy_clients(false);

        assert!(!options.allow_legacy_clients);
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_allow_navigation_requests_disabled_when_validate_then_ok() {
        let options = FetchMetadataOptions::new()
            .allow_navigation_requests(false)
            .navigation_destinations([]);

        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_navigation_destinations_empty_and_navigation_enabled_when_validate_then_error() {
        let options = FetchMetadataOptions::new().navigation_destinations([]);

        let error = options
            .validate()
            .expect_err("expected destination validation failure");

        assert_eq!(
            error,
            FetchMetadataOptionsError::EmptyNavigationDestinations
        );
    }
}
