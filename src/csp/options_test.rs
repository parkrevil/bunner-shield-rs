use super::*;

mod prefix {
    use super::*;

    #[test]
    fn given_sha256_algorithm_when_prefix_then_returns_sha256_marker() {
        assert_eq!(CspHashAlgorithm::Sha256.prefix(), "sha256-");
    }

    #[test]
    fn given_sha512_algorithm_when_prefix_then_returns_sha512_marker() {
        assert_eq!(CspHashAlgorithm::Sha512.prefix(), "sha512-");
    }
}

mod as_str {
    use super::*;

    #[test]
    fn given_default_src_directive_when_as_str_then_returns_default_src_name() {
        assert_eq!(CspDirective::DefaultSrc.as_str(), "default-src");
    }

    #[test]
    fn given_trusted_types_directive_when_as_str_then_returns_trusted_types_name() {
        assert_eq!(CspDirective::TrustedTypes.as_str(), "trusted-types");
    }
}

mod from_str {
    use super::*;

    #[test]
    fn given_known_token_when_from_str_then_returns_matching_variant() {
        let token = SandboxToken::from_str("allow-popups");

        assert_eq!(token, Some(SandboxToken::AllowPopups));
    }

    #[test]
    fn given_unknown_token_when_from_str_then_returns_none() {
        let token = SandboxToken::from_str("allow-everything");

        assert!(token.is_none());
    }
}

mod new {
    use super::*;

    #[test]
    fn given_valid_name_when_new_then_returns_policy_instance() {
        let policy = TrustedTypesPolicy::new("trustedPolicy").expect("policy should be valid");

        assert_eq!(policy.as_str(), "trustedPolicy");
    }

    #[test]
    fn given_empty_name_when_new_then_returns_empty_error() {
        let error = TrustedTypesPolicy::new("").expect_err("expected empty error");

        assert_eq!(error, TrustedTypesPolicyError::Empty);
    }

    #[test]
    fn given_invalid_characters_when_new_then_returns_invalid_name_error() {
        let error = TrustedTypesPolicy::new("1policy").expect_err("expected invalid name error");

        assert_eq!(
            error,
            TrustedTypesPolicyError::InvalidName("1policy".to_string())
        );
    }
}

mod into_string {
    use super::*;

    #[test]
    fn given_allow_duplicates_token_when_into_string_then_returns_literal() {
        let token = TrustedTypesToken::allow_duplicates();

        assert_eq!(token.into_string(), "'allow-duplicates'");
    }

    #[test]
    fn given_policy_token_when_into_string_then_returns_policy_name() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("policy should be valid");
        let token = TrustedTypesToken::from(policy);

        assert_eq!(token.into_string(), "appPolicy");
    }
}

mod to_string {
    use super::*;

    #[test]
    fn given_nonce_source_with_padding_when_display_then_trims_and_formats_value() {
        let source = CspSource::Nonce("  token-value  ".to_string());

        assert_eq!(source.to_string(), "'nonce-token-value'");
    }

    #[test]
    fn given_hash_source_with_quotes_when_display_then_sanitizes_token() {
        let source = CspSource::Hash {
            algorithm: CspHashAlgorithm::Sha384,
            value: " 'abc' ".to_string(),
        };

        assert_eq!(source.to_string(), "'sha384-abc'");
    }
}

mod with_size {
    use super::*;

    #[test]
    fn given_zero_length_when_with_size_then_returns_invalid_length_error() {
        let error = CspNonceManager::with_size(0).expect_err("expected invalid length error");

        assert_eq!(error, CspNonceManagerError::InvalidLength);
    }
}

mod issue_header_value {
    use super::*;

    #[test]
    fn given_manager_when_issue_header_value_then_returns_nonce_prefix() {
        let manager = CspNonceManager::with_size(8).expect("manager should be created");

        let header = manager.issue_header_value();

        assert!(header.starts_with("'nonce-"));
        assert!(header.len() > 8);
    }
}

mod generate_nonce_with_size {
    use super::*;

    #[test]
    fn given_zero_length_when_generate_nonce_with_size_then_returns_empty_string() {
        let nonce = CspOptions::generate_nonce_with_size(0);

        assert!(nonce.is_empty());
    }
}

mod default_src {
    use super::*;

    #[test]
    fn given_sources_with_duplicates_when_default_src_then_stores_unique_sources() {
        let options = CspOptions::new().default_src([
            CspSource::SelfKeyword,
            CspSource::SelfKeyword,
            CspSource::Wildcard,
        ]);

        assert_eq!(
            options.directives,
            vec![("default-src".to_string(), "'self' *".to_string())]
        );
    }
}

mod script_src_nonce {
    use super::*;

    #[test]
    fn given_nonce_with_quotes_when_script_src_nonce_then_sanitizes_token_entry() {
        let options = CspOptions::new().script_src_nonce(" 'nonce value' ");

        assert_eq!(
            options.directives,
            vec![("script-src".to_string(), "'nonce-nonce value'".to_string())]
        );
    }
}

mod base_uri {
    use super::*;

    #[test]
    fn given_sources_when_base_uri_then_adds_base_uri_directive() {
        let options = CspOptions::new().base_uri([CspSource::SelfKeyword]);

        let value = options.header_value();

        assert!(value.contains("base-uri 'self'"));
    }
}

mod connect_src {
    use super::*;

    #[test]
    fn given_sources_when_connect_src_then_adds_connect_src_directive() {
        let options = CspOptions::new().connect_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("connect-src 'self'"));
    }
}

mod font_src {
    use super::*;

    #[test]
    fn given_sources_when_font_src_then_adds_font_src_directive() {
        let options = CspOptions::new().font_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("font-src 'self'"));
    }
}

mod form_action {
    use super::*;

    #[test]
    fn given_sources_when_form_action_then_adds_form_action_directive() {
        let options = CspOptions::new().form_action([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("form-action 'self'"));
    }
}

mod frame_ancestors {
    use super::*;

    #[test]
    fn given_sources_when_frame_ancestors_then_adds_frame_ancestors_directive() {
        let options = CspOptions::new().frame_ancestors([CspSource::None]);

        assert!(options.header_value().contains("frame-ancestors 'none'"));
    }
}

mod frame_src {
    use super::*;

    #[test]
    fn given_sources_when_frame_src_then_adds_frame_src_directive() {
        let options = CspOptions::new().frame_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("frame-src 'self'"));
    }
}

mod img_src {
    use super::*;

    #[test]
    fn given_sources_when_img_src_then_adds_img_src_directive() {
        let options = CspOptions::new().img_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("img-src 'self'"));
    }
}

mod manifest_src {
    use super::*;

    #[test]
    fn given_sources_when_manifest_src_then_adds_manifest_src_directive() {
        let options = CspOptions::new().manifest_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("manifest-src 'self'"));
    }
}

mod media_src {
    use super::*;

    #[test]
    fn given_sources_when_media_src_then_adds_media_src_directive() {
        let options = CspOptions::new().media_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("media-src 'self'"));
    }
}

mod object_src {
    use super::*;

    #[test]
    fn given_sources_when_object_src_then_adds_object_src_directive() {
        let options = CspOptions::new().object_src([CspSource::None]);

        assert!(options.header_value().contains("object-src 'none'"));
    }
}

mod script_src_elem {
    use super::*;

    #[test]
    fn given_sources_when_script_src_elem_then_adds_script_src_elem_directive() {
        let options = CspOptions::new().script_src_elem([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("script-src-elem 'self'"));
    }
}

mod script_src_attr {
    use super::*;

    #[test]
    fn given_sources_when_script_src_attr_then_adds_script_src_attr_directive() {
        let options = CspOptions::new().script_src_attr([CspSource::UnsafeInline]);

        assert!(
            options
                .header_value()
                .contains("script-src-attr 'unsafe-inline'")
        );
    }
}

mod style_src_elem {
    use super::*;

    #[test]
    fn given_sources_when_style_src_elem_then_adds_style_src_elem_directive() {
        let options = CspOptions::new().style_src_elem([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("style-src-elem 'self'"));
    }
}

mod style_src_attr {
    use super::*;

    #[test]
    fn given_sources_when_style_src_attr_then_adds_style_src_attr_directive() {
        let options = CspOptions::new().style_src_attr([CspSource::UnsafeInline]);

        assert!(
            options
                .header_value()
                .contains("style-src-attr 'unsafe-inline'")
        );
    }
}

mod worker_src {
    use super::*;

    #[test]
    fn given_sources_when_worker_src_then_adds_worker_src_directive() {
        let options = CspOptions::new().worker_src([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("worker-src 'self'"));
    }
}

mod report_to {
    use super::*;

    #[test]
    fn given_endpoint_when_report_to_then_adds_report_to_directive() {
        let options = CspOptions::new().report_to("default");

        assert!(options.header_value().contains("report-to default"));
    }
}

mod trusted_types_policies {
    use super::*;

    #[test]
    fn given_policy_when_trusted_types_policies_then_adds_trusted_types_directive() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("valid policy");
        let options = CspOptions::new().trusted_types_policies([policy]);

        assert!(options.header_value().contains("trusted-types appPolicy"));
    }
}

mod require_trusted_types_for_scripts {
    use super::*;

    #[test]
    fn given_script_requirement_when_require_trusted_types_for_scripts_then_adds_directive() {
        let options = CspOptions::new().require_trusted_types_for_scripts();

        assert!(
            options
                .header_value()
                .contains("require-trusted-types-for 'script'")
        );
    }
}

mod upgrade_insecure_requests {
    use super::*;

    #[test]
    fn given_options_when_upgrade_insecure_requests_then_adds_flag_directive() {
        let options = CspOptions::new().upgrade_insecure_requests();

        assert!(options.header_value().contains("upgrade-insecure-requests"));
    }
}

mod block_all_mixed_content {
    use super::*;

    #[test]
    fn given_options_when_block_all_mixed_content_then_adds_flag_directive() {
        let options = CspOptions::new().block_all_mixed_content();

        assert!(options.header_value().contains("block-all-mixed-content"));
    }
}

mod sandbox_with {
    use super::*;

    #[test]
    fn given_tokens_when_sandbox_with_then_adds_sandbox_directive() {
        let options =
            CspOptions::new().sandbox_with([SandboxToken::AllowForms, SandboxToken::AllowScripts]);

        let value = options.header_value();

        assert!(value.contains("sandbox"));
        assert!(value.contains("allow-forms"));
        assert!(value.contains("allow-scripts"));
    }
}

mod sandbox {
    use super::*;

    #[test]
    fn given_no_tokens_when_sandbox_then_adds_empty_sandbox_directive() {
        let options = CspOptions::new().sandbox();

        let value = options.header_value();

        assert!(value.contains("sandbox"));
    }
}

mod navigate_to {
    use super::*;

    #[test]
    fn given_sources_when_navigate_to_then_adds_navigate_to_directive() {
        let options = CspOptions::new().navigate_to([CspSource::SelfKeyword]);

        assert!(options.header_value().contains("navigate-to 'self'"));
    }
}

mod validate_with_warnings {
    use super::*;

    #[test]
    fn given_no_worker_script_or_default_when_validate_with_warnings_then_emits_missing_worker_fallback_critical()
     {
        // no worker-src, no script-src, no default-src, but at least one directive present
        let options = CspOptions::new().base_uri([CspSource::SelfKeyword]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Critical,
                kind: CspOptionsWarningKind::MissingWorkerSrcFallback,
            }
        )));
    }

    #[test]
    fn given_permissive_default_only_when_validate_with_warnings_then_emits_weak_worker_fallback_warning()
     {
        // default-src * without worker-src/script-src -> weak fallback
        let options = CspOptions::new().default_src([CspSource::Wildcard]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Warning,
                kind: CspOptionsWarningKind::WeakWorkerSrcFallback,
            }
        )));
    }

    #[test]
    fn given_upgrade_without_block_when_validate_with_warnings_then_emits_dependency_warning() {
        let options = CspOptions::new().upgrade_insecure_requests();

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Warning,
                kind: CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
            }
        )));
    }

    #[test]
    fn given_block_without_upgrade_when_validate_with_warnings_then_emits_dependency_warning() {
        let options = CspOptions::new().block_all_mixed_content();

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        assert!(warnings.iter().any(|w| matches!(
            w,
            CspOptionsWarning {
                severity: CspWarningSeverity::Warning,
                kind: CspOptionsWarningKind::BlockAllMixedContentWithoutUpgradeInsecureRequests,
            }
        )));
    }

    #[test]
    fn given_risky_schemes_when_validate_with_warnings_then_aggregates_by_directive_with_max_severity()
     {
        // style-src includes data: (Critical) and blob: (Warning) -> overall Critical with schemes ["blob", "data"]
        // img-src includes filesystem: (Critical) -> Critical with schemes ["filesystem"]
        let options = CspOptions::new()
            .style_src([
                CspSource::raw("data:"),
                CspSource::raw("blob:"),
                CspSource::SelfKeyword,
            ])
            .img_src([
                CspSource::raw("filesystem:"),
                CspSource::host("cdn.example.com"),
            ]);

        let mut warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        // retain only RiskySchemes warnings for easier assertions
        warnings.retain(|w| matches!(w.kind, CspOptionsWarningKind::RiskySchemes { .. }));

        // there should be exactly two aggregated entries (for style-src and img-src)
        assert_eq!(warnings.len(), 2);

        // sort for deterministic assertions
        warnings.sort_by(|a, b| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)));

        // assert style-src aggregation
        let style_warning = warnings
            .iter()
            .find(|w| match &w.kind {
                CspOptionsWarningKind::RiskySchemes { directive, .. } => directive == "style-src",
                _ => false,
            })
            .expect("style-src risky schemes warning");
        assert!(matches!(
            style_warning.severity,
            CspWarningSeverity::Critical
        ));
        if let CspOptionsWarningKind::RiskySchemes { directive, schemes } = &style_warning.kind {
            assert_eq!(directive, "style-src");
            let mut expected = vec!["blob".to_string(), "data".to_string()];
            let mut actual = schemes.clone();
            expected.sort();
            actual.sort();
            assert_eq!(actual, expected);
        } else {
            unreachable!();
        }

        // assert img-src aggregation
        let img_warning = warnings
            .iter()
            .find(|w| match &w.kind {
                CspOptionsWarningKind::RiskySchemes { directive, .. } => directive == "img-src",
                _ => false,
            })
            .expect("img-src risky schemes warning");
        assert!(matches!(img_warning.severity, CspWarningSeverity::Critical));
        if let CspOptionsWarningKind::RiskySchemes { directive, schemes } = &img_warning.kind {
            assert_eq!(directive, "img-src");
            assert_eq!(schemes, &vec!["filesystem".to_string()]);
        } else {
            unreachable!();
        }
    }
}
