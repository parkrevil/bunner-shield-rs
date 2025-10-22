use super::*;

mod new {
    use super::*;

    #[test]
    fn given_initial_policy_when_new_then_stores_policy_string() {
        let options = PermissionsPolicyOptions::new("accelerometer=()");

        assert_eq!(options.header_value(), "accelerometer=()");
    }
}

mod policy {
    use super::*;

    #[test]
    fn given_existing_options_when_policy_then_updates_policy_string() {
        let options = PermissionsPolicyOptions::new("camera=() ").policy("camera=()");

        assert_eq!(options.header_value(), "camera=()");
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_non_empty_policy_when_validate_then_returns_ok() {
        let options = PermissionsPolicyOptions::new("fullscreen=(self)");

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_empty_policy_when_validate_then_returns_empty_policy_error() {
        let options = PermissionsPolicyOptions::new("   ");

        let error = options.validate().expect_err("expected empty policy error");

        assert_eq!(error, PermissionsPolicyOptionsError::EmptyPolicy);
    }
}

mod builder_minimal {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn given_feature_entries_when_build_then_renders_canonical_policy() {
        let options = PermissionsPolicyOptions::builder()
            .feature(
                "Geolocation",
                [AllowListItem::None, AllowListItem::SelfKeyword],
            )
            .feature(
                "camera",
                [
                    AllowListItem::Origin(Cow::Borrowed(" https://a.example ")),
                    AllowListItem::Origin(Cow::Borrowed("https://a.example")), // duplicate
                    AllowListItem::Any,
                ],
            )
            .build()
            .expect("builder should succeed for valid entries");

        assert_eq!(
            options.header_value(),
            "geolocation=(() self), camera=(https://a.example *)"
        );
        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_self_only_allowlist_when_build_then_renders_without_quotes() {
        let options = PermissionsPolicyOptions::builder()
            .feature("geolocation", [AllowListItem::SelfKeyword])
            .build()
            .expect("builder should succeed for valid entries");

        assert_eq!(options.header_value(), "geolocation=(self)");
    }

    #[test]
    fn given_self_mixed_with_origins_when_build_then_preserves_order_without_quotes() {
        let options = PermissionsPolicyOptions::builder()
            .feature(
                "camera",
                [
                    AllowListItem::SelfKeyword,
                    AllowListItem::Origin(Cow::Borrowed("https://example.com")),
                    AllowListItem::SelfKeyword,
                ],
            )
            .build()
            .expect("builder should succeed for valid entries");

        assert_eq!(options.header_value(), "camera=(self https://example.com)");
    }

    #[test]
    fn given_blank_feature_name_when_build_then_returns_error() {
        let result = PermissionsPolicyOptions::builder()
            .feature("   ", [AllowListItem::None])
            .build();

        assert_eq!(result.unwrap_err(), PolicyBuilderError::EmptyFeatureName);
    }

    #[test]
    fn given_invalid_feature_name_when_build_then_returns_error() {
        // Explicit invalid samples (non-empty but not matching regex)
        for name in ["1camera", "-camera", "camera!"].iter() {
            let result = PermissionsPolicyOptions::builder()
                .feature(*name, [AllowListItem::None])
                .build();
            assert!(matches!(
                result.unwrap_err(),
                PolicyBuilderError::InvalidFeatureName(_)
            ));
        }

        // Empty or whitespace-only should still be treated as EmptyFeatureName
        let err = PermissionsPolicyOptions::builder()
            .feature("   ", [AllowListItem::None])
            .build()
            .unwrap_err();
        assert_eq!(err, PolicyBuilderError::EmptyFeatureName);

        // Valid samples ensure we don't over-reject
        for name in [
            "camera",
            "geolocation",
            "microphone",
            "camera-zoom",
            "a1",
            "Camera", // will normalize to lowercase and pass
            "camerA", // mixed case normalizes to valid
        ]
        .iter()
        {
            let result = PermissionsPolicyOptions::builder()
                .feature(*name, [AllowListItem::None])
                .build();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn given_blank_origin_allowlist_item_when_build_then_returns_error() {
        let result = PermissionsPolicyOptions::builder()
            .feature("camera", [AllowListItem::Origin(Cow::Borrowed("   "))])
            .build();

        assert_eq!(
            result.unwrap_err(),
            PolicyBuilderError::EmptyAllowListEntry {
                feature: "camera".to_string(),
            }
        );
    }

    #[test]
    fn given_allowlist_with_duplicates_when_build_then_dedup_preserves_first_order() {
        let options = PermissionsPolicyOptions::builder()
            .feature(
                "geolocation",
                [
                    AllowListItem::Origin(Cow::Borrowed("https://a.example")),
                    AllowListItem::Origin(Cow::Borrowed("https://b.example")),
                    AllowListItem::Origin(Cow::Borrowed("https://a.example")), // duplicate
                    AllowListItem::Origin(Cow::Borrowed("https://b.example")), // duplicate
                    AllowListItem::SelfKeyword,
                    AllowListItem::SelfKeyword, // duplicate
                ],
            )
            .build()
            .expect("builder should succeed");

        assert_eq!(
            options.header_value(),
            "geolocation=(https://a.example https://b.example self)"
        );
    }

    #[test]
    fn given_multiple_features_when_build_then_preserves_feature_insertion_order() {
        let options = PermissionsPolicyOptions::builder()
            .feature("camera", [AllowListItem::None])
            .feature("geolocation", [AllowListItem::SelfKeyword])
            .feature("microphone", [AllowListItem::Any])
            .build()
            .expect("builder should succeed");

        assert_eq!(
            options.header_value(),
            "camera=(()), geolocation=(self), microphone=(*)"
        );
    }
}
