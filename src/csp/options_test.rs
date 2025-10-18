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
mod risky_scheme_warnings_critical {
    use super::*;

    #[test]
    fn given_critical_schemes_when_validate_with_warnings_then_escalates_severity() {
        let options = CspOptions::new()
            .script_src(|script| {
                script.sources([CspSource::raw("data:"), CspSource::raw("filesystem:")])
            })
            .style_src(|style| style.sources([CspSource::raw("blob:")]));

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        let risky = warnings
            .iter()
            .find(|w| matches!(w.kind, CspOptionsWarningKind::RiskySchemes { .. }))
            .expect("expected risky scheme aggregation");

        assert!(matches!(risky.severity, CspWarningSeverity::Critical));

        if let CspOptionsWarningKind::RiskySchemes { directive, schemes } = &risky.kind {
            assert_eq!(directive, "script-src");
            assert_eq!(schemes, &vec!["data".to_string(), "filesystem".to_string()]);
        }
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
    use std::borrow::Cow;

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

    #[test]
    fn given_literal_variants_when_display_then_matches_expected_values() {
        let cases = [
            (CspSource::SelfKeyword, "'self'"),
            (CspSource::None, "'none'"),
            (CspSource::UnsafeInline, "'unsafe-inline'"),
            (CspSource::UnsafeEval, "'unsafe-eval'"),
            (CspSource::UnsafeHashes, "'unsafe-hashes'"),
            (CspSource::WasmUnsafeEval, "'wasm-unsafe-eval'"),
            (CspSource::StrictDynamic, "'strict-dynamic'"),
            (CspSource::ReportSample, "'report-sample'"),
            (CspSource::Wildcard, "*"),
            (CspSource::Scheme(Cow::Borrowed("data")), "data:"),
            (
                CspSource::Host(Cow::Borrowed("cdn.example.com")),
                "cdn.example.com",
            ),
            (
                CspSource::Custom("custom-token".to_string()),
                "custom-token",
            ),
        ];

        for (source, expected) in cases {
            assert_eq!(source.to_string(), expected);
        }
    }
}

mod script_source_helpers {
    use super::*;

    #[test]
    fn given_helper_methods_when_invoked_then_append_expected_tokens() {
        let options = CspOptions::new()
            .script_src(|script| {
                script
                    .nonce_value(CspNonce {
                        value: " helper-nonce ".to_string(),
                    })
                    .nonce("  inline-nonce  ")
                    .hash(CspHashAlgorithm::Sha512, " 'hash-value' ")
                    .strict_dynamic()
            })
            .require_trusted_types_for_scripts();

        let script_value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value");
        assert!(script_value.contains("'nonce-helper-nonce'"));
        assert!(script_value.contains("'nonce-inline-nonce'"));
        assert!(script_value.contains("'sha512-hash-value'"));
        assert!(script_value.contains("'strict-dynamic'"));

        let require_value = options
            .directive_value(CspDirective::RequireTrustedTypesFor.as_str())
            .expect("require-trusted-types-for value");
        assert_eq!(require_value, "'script'");
    }
}

mod script_element_helpers {
    use super::*;

    #[test]
    fn given_element_helpers_when_invoked_then_add_expected_tokens() {
        let options = CspOptions::new().script_src(|script| {
            script
                .elem_nonce(" elem-nonce ")
                .elem_hash(CspHashAlgorithm::Sha256, " elem-hash ")
                .attr_nonce(" attr-nonce ")
                .attr_hash(CspHashAlgorithm::Sha384, " attr-hash ")
        });

        let elem_value = options
            .directive_value(CspDirective::ScriptSrcElem.as_str())
            .expect("script-src-elem value");
        assert!(elem_value.contains("'nonce-elem-nonce'"));
        assert!(elem_value.contains("'sha256-elem-hash'"));

        let attr_value = options
            .directive_value(CspDirective::ScriptSrcAttr.as_str())
            .expect("script-src-attr value");
        assert!(attr_value.contains("'nonce-attr-nonce'"));
        assert!(attr_value.contains("'sha384-attr-hash'"));
    }
}

mod style_source_helpers {
    use super::*;

    #[test]
    fn given_style_helpers_when_invoked_then_add_expected_tokens() {
        let options = CspOptions::new().style_src(|style| {
            style
                .nonce(" style-nonce ")
                .hash(CspHashAlgorithm::Sha384, " style-hash ")
                .elem_nonce(" style-elem-nonce ")
                .elem_hash(CspHashAlgorithm::Sha512, " style-elem-hash ")
                .attr_nonce(" style-attr-nonce ")
                .attr_hash(CspHashAlgorithm::Sha256, " style-attr-hash ")
        });

        let style_value = options
            .directive_value(CspDirective::StyleSrc.as_str())
            .expect("style-src value");
        assert!(style_value.contains("'nonce-style-nonce'"));
        assert!(style_value.contains("'sha384-style-hash'"));

        let elem_value = options
            .directive_value(CspDirective::StyleSrcElem.as_str())
            .expect("style-src-elem value");
        assert!(elem_value.contains("'nonce-style-elem-nonce'"));
        assert!(elem_value.contains("'sha512-style-elem-hash'"));

        let attr_value = options
            .directive_value(CspDirective::StyleSrcAttr.as_str())
            .expect("style-src-attr value");
        assert!(attr_value.contains("'nonce-style-attr-nonce'"));
        assert!(attr_value.contains("'sha256-style-attr-hash'"));
    }
}

mod runtime_nonce {
    use super::*;

    #[test]
    fn given_runtime_nonce_configuration_when_render_then_substitutes_placeholder() {
        let options = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::with_size(18).expect("nonce size"))
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| script.runtime_nonce().strict_dynamic());

        let placeholder_header = options.header_value();
        let config = options
            .runtime_nonce_config()
            .expect("runtime nonce config should exist");

        let placeholder_token = config
            .directives()
            .find(|(name, _)| name.as_str() == "script-src")
            .map(|(_, token)| token.clone())
            .expect("placeholder token for script-src");
        assert!(placeholder_header.contains(&placeholder_token));
        assert!(placeholder_header.contains("'strict-dynamic'"));

        let rendered = options.render_with_runtime_nonce("dynamic-nonce-value");
        assert!(rendered.contains("default-src 'self'"));
        assert!(rendered.contains("'strict-dynamic'"));
        assert!(rendered.contains("'nonce-dynamic-nonce-value'"));
        assert!(!rendered.contains(&placeholder_token));

        // Ensure configuration still retains placeholder for future invocations
        let config_after = options
            .runtime_nonce_config()
            .expect("runtime nonce config should persist");
        let retained = config_after
            .directives()
            .find(|(name, _)| name.as_str() == "script-src")
            .map(|(_, token)| token.clone())
            .expect("retained placeholder");
        assert_eq!(retained, placeholder_token);
    }

    #[test]
    fn given_style_runtime_nonce_helper_when_used_then_registers_placeholder() {
        let options = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::new())
            .style_src(|style| style.runtime_nonce());

        let config = options
            .runtime_nonce_config()
            .expect("runtime nonce config should exist");
        let placeholder = config
            .directives()
            .find(|(name, _)| name.as_str() == "style-src")
            .map(|(_, token)| token.clone())
            .expect("style-src placeholder");

        let header = options.render_with_runtime_nonce("abc123");
        assert!(header.contains("style-src 'nonce-abc123'"));
        assert!(options.header_value().contains(&placeholder));
    }

    #[test]
    fn given_runtime_nonce_options_merge_when_combined_then_preserves_placeholders() {
        let base = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::new())
            .script_src(|script| script.runtime_nonce());
        let overlay = CspOptions::new().style_src(|style| style.runtime_nonce());

        let merged = base.merge(&overlay);
        let config = merged
            .runtime_nonce_config()
            .expect("merged runtime nonce config");

        let directive_names: std::collections::HashSet<_> =
            config.directives().map(|(name, _)| name.clone()).collect();
        assert!(directive_names.contains("script-src"));
        assert!(directive_names.contains("style-src"));

        let header = merged.render_with_runtime_nonce("nonce-value");
        assert!(header.contains("script-src 'nonce-nonce-value'"));
        assert!(header.contains("style-src 'nonce-nonce-value'"));
    }
}

mod nonce_generation {
    use super::*;

    #[test]
    fn given_generate_nonce_when_called_then_returns_base64_value() {
        let value = CspOptions::generate_nonce();

        assert_eq!(value.len(), 44);
        assert!(value.is_ascii());
    }
}

mod directive_name_validation {
    use super::*;

    #[test]
    fn given_known_directive_when_validate_name_then_returns_true() {
        assert!(CspOptions::is_valid_directive_name("script-src"));
    }

    #[test]
    fn given_unknown_directive_when_validate_name_then_returns_false() {
        assert!(!CspOptions::is_valid_directive_name("unknown-directive"));
    }
}

mod add_source_behavior {
    use super::*;

    #[test]
    fn given_blank_source_when_add_source_then_ignores_entry() {
        let options = CspOptions::new().add_source(CspDirective::ScriptSrc, "   ");

        assert!(options.directives.is_empty());
    }

    #[test]
    fn given_existing_directive_when_add_source_then_appends_unique_token() {
        let options = CspOptions::new()
            .script_src(|script| script.sources([CspSource::SelfKeyword]))
            .add_source(CspDirective::ScriptSrc, CspSource::host("cdn.example.com"));

        let value = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .expect("script-src value should exist");

        assert!(value.contains("'self'"));
        assert!(value.contains("cdn.example.com"));
        assert!(value.contains("'self' cdn.example.com"));
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
        let options = CspOptions::new().script_src(|script| script.nonce(" 'nonce value' "));

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
        let options = CspOptions::new().script_src(|script| script.elem([CspSource::SelfKeyword]));

        assert!(options.header_value().contains("script-src-elem 'self'"));
    }
}

mod script_src_attr {
    use super::*;

    #[test]
    fn given_sources_when_script_src_attr_then_adds_script_src_attr_directive() {
        let options = CspOptions::new().script_src(|script| script.attr([CspSource::UnsafeInline]));

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
        let options = CspOptions::new().style_src(|style| style.elem([CspSource::SelfKeyword]));

        assert!(options.header_value().contains("style-src-elem 'self'"));
    }
}

mod style_src_attr {
    use super::*;

    #[test]
    fn given_sources_when_style_src_attr_then_adds_style_src_attr_directive() {
        let options = CspOptions::new().style_src(|style| style.attr([CspSource::UnsafeInline]));

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

mod trusted_types_builder {
    use super::*;

    #[test]
    fn given_policy_when_trusted_types_policy_then_adds_trusted_types_directive() {
        let policy = TrustedTypesPolicy::new("appPolicy").expect("valid policy");
        let options = CspOptions::new().trusted_types(|trusted| trusted.policy(policy));

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
            .style_src(|style| {
                style.sources([
                    CspSource::raw("data:"),
                    CspSource::raw("blob:"),
                    CspSource::SelfKeyword,
                ])
            })
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

mod warning_utilities {
    use super::*;

    #[test]
    fn given_info_levels_when_max_then_returns_info() {
        assert_eq!(
            CspWarningSeverity::Info.max(CspWarningSeverity::Info),
            CspWarningSeverity::Info
        );
        assert_eq!(
            CspWarningSeverity::Warning.max(CspWarningSeverity::Info),
            CspWarningSeverity::Warning
        );
    }

    #[test]
    fn given_warning_constructors_when_invoked_then_set_expected_severity() {
        let info = CspOptionsWarning::info(CspOptionsWarningKind::WeakWorkerSrcFallback);
        assert!(matches!(info.severity, CspWarningSeverity::Info));

        let warning = CspOptionsWarning::warning(
            CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
        );
        assert!(matches!(warning.severity, CspWarningSeverity::Warning));

        let critical = CspOptionsWarning::critical(CspOptionsWarningKind::MissingWorkerSrcFallback);
        assert!(matches!(critical.severity, CspWarningSeverity::Critical));
    }
}

mod from_impls {
    use super::*;

    #[test]
    fn given_str_when_from_then_returns_custom_source() {
        let source = CspSource::from("inline-script");

        assert!(matches!(source, CspSource::Custom(value) if value == "inline-script"));
    }

    #[test]
    fn given_string_when_from_then_returns_custom_source() {
        let source = CspSource::from("cdn".to_string());

        assert!(matches!(source, CspSource::Custom(value) if value == "cdn"));
    }

    #[test]
    fn given_nonce_when_from_then_returns_nonce_variant() {
        let nonce = CspNonce {
            value: "nonce-value".to_string(),
        };

        let source = CspSource::from(nonce.clone());

        assert!(matches!(source, CspSource::Nonce(value) if value == nonce.value));
    }
}

mod sandbox_tokens {
    use super::*;

    #[test]
    fn given_all_sandbox_tokens_when_as_str_then_returns_expected_literals() {
        let expectations = [
            (SandboxToken::AllowDownloads, "allow-downloads"),
            (SandboxToken::AllowForms, "allow-forms"),
            (SandboxToken::AllowModals, "allow-modals"),
            (SandboxToken::AllowOrientationLock, "allow-orientation-lock"),
            (SandboxToken::AllowPointerLock, "allow-pointer-lock"),
            (SandboxToken::AllowPopups, "allow-popups"),
            (
                SandboxToken::AllowPopupsToEscapeSandbox,
                "allow-popups-to-escape-sandbox",
            ),
            (SandboxToken::AllowPresentation, "allow-presentation"),
            (SandboxToken::AllowSameOrigin, "allow-same-origin"),
            (SandboxToken::AllowScripts, "allow-scripts"),
            (
                SandboxToken::AllowStorageAccessByUserActivation,
                "allow-storage-access-by-user-activation",
            ),
            (SandboxToken::AllowTopNavigation, "allow-top-navigation"),
            (
                SandboxToken::AllowTopNavigationByUserActivation,
                "allow-top-navigation-by-user-activation",
            ),
            (
                SandboxToken::AllowTopNavigationToCustomProtocols,
                "allow-top-navigation-to-custom-protocols",
            ),
            (
                SandboxToken::AllowDownloadsWithoutUserActivation,
                "allow-downloads-without-user-activation",
            ),
        ];

        for (token, expected) in expectations {
            assert_eq!(token.as_str(), expected);
            assert_eq!(SandboxToken::from_str(expected), Some(token));
        }
    }
}

mod trusted_types_helpers {
    use super::*;

    #[test]
    fn given_policy_when_using_constructors_then_returns_expected_variants() {
        let policy = TrustedTypesPolicy::new("frontendPolicy").expect("policy should be valid");

        assert!(
            matches!(TrustedTypesToken::policy(policy.clone()), TrustedTypesToken::Policy(p) if p == policy)
        );
        assert!(matches!(
            TrustedTypesToken::allow_duplicates(),
            TrustedTypesToken::AllowDuplicates
        ));
    }
}

mod nonce_utilities {
    use super::*;

    #[test]
    fn given_nonce_when_accessors_invoked_then_returns_expected_views() {
        let nonce = CspNonce {
            value: "abc123".to_string(),
        };

        assert_eq!(nonce.as_str(), "abc123");
        assert_eq!(nonce.header_value(), "'nonce-abc123'");
        assert_eq!(nonce.clone().into_inner(), "abc123".to_string());
    }

    #[test]
    fn given_manager_when_querying_byte_length_then_returns_configured_value() {
        assert_eq!(CspNonceManager::new().byte_len(), 32);
        let manager = CspNonceManager::with_size(12).expect("non-zero length");
        assert_eq!(manager.byte_len(), 12);
    }
}

mod nonce_manager_behaviour {
    use super::*;

    #[test]
    fn given_default_manager_when_issue_then_uses_default_length() {
        let manager = CspNonceManager::default();
        let nonce = manager.issue();

        assert_eq!(manager.byte_len(), CspNonceManager::new().byte_len());
        assert_eq!(nonce.as_str().len(), 44);
        assert!(nonce.as_str().is_ascii());
    }
}

mod merge_edge_cases {
    use super::*;

    #[test]
    fn given_missing_report_to_when_merge_then_copies_overlay_group() {
        let base = CspOptions::new().default_src([CspSource::SelfKeyword]);
        let overlay = CspOptions::new().report_to("primary");

        let merged = base.merge(&overlay);

        assert!(merged.header_value().contains("report-to primary"));
    }

    #[test]
    fn given_empty_overlay_directive_when_merge_then_preserves_blank_value() {
        let base = CspOptions::new();
        let overlay = CspOptions {
            directives: vec![("img-src".to_string(), "   ".to_string())],
            runtime_nonce: None,
        };

        let merged = base.merge(&overlay);

        assert!(
            merged
                .directives
                .iter()
                .any(|(name, value)| name == "img-src" && value.trim().is_empty())
        );
    }

    #[test]
    fn given_existing_value_when_merge_blank_overlay_then_retains_original_sources() {
        let base = CspOptions::new().img_src([CspSource::SelfKeyword]);
        let overlay = CspOptions {
            directives: vec![("img-src".to_string(), "   ".to_string())],
            runtime_nonce: None,
        };

        let merged = base.clone().merge(&overlay);

        let original = base
            .directive_value(CspDirective::ImgSrc.as_str())
            .expect("base directive");
        let merged_value = merged
            .directive_value(CspDirective::ImgSrc.as_str())
            .expect("merged directive");

        assert_eq!(merged_value, original);
    }
}

mod directive_helpers {
    use super::*;

    #[test]
    fn given_duplicate_source_when_add_source_then_deduplicates_token() {
        let options = CspOptions::new()
            .connect_src([CspSource::SelfKeyword])
            .add_source(CspDirective::ConnectSrc, CspSource::host("api.example.com"));

        let header = options.header_value();
        assert!(header.contains("connect-src 'self' api.example.com"));
    }

    #[test]
    fn given_sources_with_empty_segment_when_format_sources_then_skips_segment() {
        let formatted = format_sources([
            CspSource::from(""),
            CspSource::SelfKeyword,
            CspSource::Custom("".to_string()),
        ]);

        assert_eq!(formatted, "'self'");
    }

    #[test]
    fn given_invalid_directive_name_when_validate_then_returns_error() {
        let options = CspOptions {
            directives: vec![("bogus".to_string(), "value".to_string())],
            runtime_nonce: None,
        };

        let error = options
            .validate_with_warnings()
            .expect_err("expected invalid directive name");

        assert_eq!(error, CspOptionsError::InvalidDirectiveName);
    }
}

mod internal_validation {
    use super::*;

    #[test]
    fn given_empty_token_when_validate_token_then_returns_invalid_directive_value() {
        let error =
            CspOptions::validate_token("default-src", "").expect_err("empty tokens are invalid");

        assert_eq!(error, CspOptionsError::InvalidDirectiveValue);
    }

    #[test]
    fn given_scheme_with_slash_when_enforce_scheme_restrictions_then_allows_value() {
        CspOptions::enforce_scheme_restrictions("script-src", "custom/path:")
            .expect("slash-terminated scheme should be allowed");
    }

    #[test]
    fn given_host_with_query_when_validate_host_like_source_then_returns_error() {
        let error = CspOptions::validate_host_like_source(
            "https://example.com?query=1",
            "https://example.com?query=1",
        )
        .expect_err("queries are not permitted");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression("https://example.com?query=1".to_string())
        );
    }

    #[test]
    fn given_empty_wildcard_suffix_when_validate_wildcard_host_then_returns_error() {
        let token = "*.";
        let error = CspOptions::validate_wildcard_host(token)
            .expect_err("bare wildcard host should be invalid");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_control_character_path_when_validate_path_source_then_returns_error() {
        let token = "/admin\u{0007}";
        let error =
            CspOptions::validate_path_source(token).expect_err("control characters are disallowed");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_whitespace_in_source_expression_when_validate_source_expression_then_returns_error() {
        let token = "example.com path";
        let error = CspOptions::validate_source_expression(token)
            .expect_err("whitespace should be rejected in source expressions");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_absolute_path_when_validate_source_expression_then_returns_ok() {
        CspOptions::validate_source_expression("/assets/static")
            .expect("absolute paths should be accepted");
    }

    #[test]
    fn given_wildcard_host_when_validate_source_expression_then_returns_ok() {
        CspOptions::validate_source_expression("*.media.example")
            .expect("wildcard hosts should be accepted");
    }

    #[test]
    fn given_scheme_without_host_when_validate_host_like_source_then_returns_error() {
        let token = "https://@/";
        let error = CspOptions::validate_host_like_source(token, token)
            .expect_err("missing hosts should be rejected");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_port_wildcard_with_suffix_when_normalize_then_returns_expression_error() {
        let error = CspOptions::normalize_port_wildcard(
            "https://example.com:*svc".to_string(),
            "https://example.com:*svc",
        )
        .expect_err("suffix after wildcard should be invalid");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression("https://example.com:*svc".to_string())
        );
    }

    #[test]
    fn given_strict_dynamic_and_self_when_checking_host_sources_then_detects_conflict() {
        let script_src = "'strict-dynamic' 'self'";
        assert!(CspOptions::strict_dynamic_has_host_sources(
            Some(script_src),
            None
        ));
    }

    #[test]
    fn given_strict_dynamic_with_nonce_only_when_validating_host_sources_then_allows() {
        CspOptions::validate_strict_dynamic_host_sources(
            Some("'strict-dynamic' 'nonce-token'"),
            None,
        )
        .expect("nonce backed strict-dynamic should be accepted");
    }

    #[test]
    fn given_valid_wildcard_host_when_validate_wildcard_host_then_returns_ok() {
        CspOptions::validate_wildcard_host("*.example.org")
            .expect("wildcard host should be accepted");
    }

    #[test]
    fn given_absolute_path_when_validate_path_source_then_returns_ok() {
        CspOptions::validate_path_source("/assets/scripts")
            .expect("leading slash paths should be accepted");
    }

    #[test]
    fn given_star_token_when_validate_source_expression_then_returns_ok() {
        CspOptions::validate_source_expression("*")
            .expect("asterisk source should always be valid");
    }

    #[test]
    fn given_scheme_only_when_validate_source_expression_then_returns_ok() {
        CspOptions::validate_source_expression("https:").expect("scheme tokens should be accepted");
    }

    #[test]
    fn given_invalid_scheme_prefix_when_validate_source_expression_then_returns_error() {
        let token = "1invalid:";
        let error = CspOptions::validate_source_expression(token)
            .expect_err("schemes must start with an alphabetic character");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_host_with_fragment_when_validate_source_expression_then_returns_error() {
        let token = "https://example.com/path#frag";
        let error = CspOptions::validate_source_expression(token)
            .expect_err("fragments are not permitted in source expressions");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_cached_token_when_validate_source_expression_cached_then_reuses_result() {
        let mut cache = TokenValidationCache::default();

        CspOptions::validate_source_expression_cached("https://cdn.example.com", &mut cache)
            .expect("initial validation should succeed");

        let cached =
            CspOptions::validate_source_expression_cached("https://cdn.example.com", &mut cache);

        assert!(
            cached.is_ok(),
            "cached validation should reuse stored result"
        );
    }

    #[test]
    fn given_special_tokens_when_checking_host_sources_then_ignores_non_host_entries() {
        let tokens = "'strict-dynamic' 'report-sample' 'wasm-unsafe-eval' 'nonce-value'";

        assert!(
            !CspOptions::strict_dynamic_has_host_sources(Some(tokens), None),
            "non-host special tokens should not trigger host detection"
        );
    }

    #[test]
    fn given_nested_wildcard_when_validate_wildcard_host_then_returns_error() {
        let token = "*.api*.example.com";
        let error = CspOptions::validate_wildcard_host(token)
            .expect_err("multiple wildcard segments should be rejected");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_relative_path_when_validate_path_source_then_returns_error() {
        let token = "assets/script.js";
        let error = CspOptions::validate_path_source(token)
            .expect_err("relative paths are invalid in source expressions");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_scheme_with_invalid_character_when_validate_source_expression_then_returns_error() {
        let token = "http$:";
        let error = CspOptions::validate_source_expression(token)
            .expect_err("invalid characters are not allowed in schemes");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_credentials_in_host_when_validate_source_expression_then_returns_error() {
        let token = "https://user@cdn.example.com";
        let error = CspOptions::validate_source_expression(token)
            .expect_err("credentials should be rejected");

        assert_eq!(
            error,
            CspOptionsError::InvalidSourceExpression(token.to_string())
        );
    }

    #[test]
    fn given_host_without_scheme_when_validate_source_expression_then_returns_ok() {
        CspOptions::validate_source_expression("cdn.example.com")
            .expect("host-only entries should be accepted");
    }

    #[test]
    fn given_port_wildcard_followed_by_path_when_normalize_then_returns_port_wildcard_error() {
        let error = CspOptions::normalize_port_wildcard(
            "https://example.com:*/path".to_string(),
            "https://example.com:*/path",
        )
        .expect_err("port wildcard should not be followed by a path");

        assert_eq!(
            error,
            CspOptionsError::PortWildcardUnsupported("https://example.com:*/path".to_string())
        );
    }
}

mod directive_support_matrix {
    use super::*;

    #[test]
    fn given_support_queries_when_directive_helpers_then_report_expected_capabilities() {
        assert!(CspOptions::directive_supports_nonces("script-src"));
        assert!(CspOptions::directive_supports_nonces("style-src"));
        assert!(!CspOptions::directive_supports_nonces("img-src"));

        assert!(CspOptions::directive_supports_hashes("script-src-elem"));
        assert!(CspOptions::directive_supports_hashes("style-src-attr"));
        assert!(!CspOptions::directive_supports_hashes("connect-src"));

        assert!(CspOptions::directive_supports_strict_dynamic("script-src"));
        assert!(!CspOptions::directive_supports_strict_dynamic(
            "script-src-attr"
        ));

        assert!(CspOptions::directive_supports_unsafe_inline("style-src"));
        assert!(!CspOptions::directive_supports_unsafe_inline("img-src"));

        assert!(CspOptions::directive_supports_unsafe_eval("script-src"));
        assert!(!CspOptions::directive_supports_unsafe_eval("style-src"));

        assert!(CspOptions::directive_supports_unsafe_hashes("style-src"));
        assert!(!CspOptions::directive_supports_unsafe_hashes(
            "script-src-elem"
        ));

        assert!(CspOptions::directive_supports_wasm_unsafe_eval(
            "script-src"
        ));
        assert!(!CspOptions::directive_supports_wasm_unsafe_eval(
            "style-src"
        ));

        assert!(CspOptions::directive_supports_report_sample(
            "style-src-elem"
        ));
        assert!(!CspOptions::directive_supports_report_sample("img-src"));

        assert!(CspOptions::directive_is_script_family("script-src-attr"));
        assert!(!CspOptions::directive_is_script_family("style-src"));

        assert!(CspOptions::directive_is_style_family("style-src-attr"));
        assert!(!CspOptions::directive_is_style_family("script-src"));

        assert!(CspOptions::directive_expects_sources("frame-ancestors"));
        assert!(!CspOptions::directive_expects_sources("trusted-types"));

        assert!(CspOptions::allows_empty_value("sandbox"));
        assert!(!CspOptions::allows_empty_value("default-src"));

        assert!(CspOptions::contains_conflicting_none(&["'none'", "'self'"]));
        assert!(!CspOptions::contains_conflicting_none(&[
            "'self'",
            "'strict-dynamic'"
        ]));

        assert!(CspOptions::is_permissive_default_source("* 'self'"));
        assert!(!CspOptions::is_permissive_default_source("'self'"));
    }
}

mod directive_value_edge_cases {
    use super::*;

    #[test]
    fn given_multiline_value_when_validate_directive_value_then_returns_invalid_token() {
        let mut cache = TokenValidationCache::default();
        let error = CspOptions::validate_directive_value(
            CspDirective::ScriptSrc.as_str(),
            "value\r\nnext",
            &mut cache,
        )
        .expect_err("embedded newlines are disallowed");

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_unsafe_hashes_without_hash_when_validate_directive_value_then_returns_error() {
        let mut cache = TokenValidationCache::default();
        let error = CspOptions::validate_directive_value(
            CspDirective::ScriptSrc.as_str(),
            "'unsafe-hashes'",
            &mut cache,
        )
        .expect_err("unsafe-hashes requires a hash expression");

        assert_eq!(
            error,
            CspOptionsError::UnsafeHashesRequireHashes(
                CspDirective::ScriptSrc.as_str().to_string()
            )
        );
    }

    #[test]
    fn given_unsafe_hashes_on_script_elem_when_validate_value_then_returns_not_allowed_error() {
        let mut cache = TokenValidationCache::default();
        let error = CspOptions::validate_directive_value(
            CspDirective::ScriptSrcElem.as_str(),
            "'unsafe-hashes'",
            &mut cache,
        )
        .expect_err("script-src-elem does not support unsafe-hashes");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'unsafe-hashes'".to_string());
                assert_eq!(directive, CspDirective::ScriptSrcElem.as_str().to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_report_sample_on_img_src_when_validate_value_then_returns_not_allowed_error() {
        let mut cache = TokenValidationCache::default();
        let error = CspOptions::validate_directive_value(
            CspDirective::ImgSrc.as_str(),
            "'report-sample'",
            &mut cache,
        )
        .expect_err("report-sample is not valid for img-src");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'report-sample'".to_string());
                assert_eq!(directive, CspDirective::ImgSrc.as_str().to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_wasm_unsafe_eval_on_style_src_when_validate_value_then_returns_not_allowed_error() {
        let mut cache = TokenValidationCache::default();
        let error = CspOptions::validate_directive_value(
            CspDirective::StyleSrc.as_str(),
            "'wasm-unsafe-eval'",
            &mut cache,
        )
        .expect_err("wasm-unsafe-eval does not apply to style-src");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'wasm-unsafe-eval'".to_string());
                assert_eq!(directive, CspDirective::StyleSrc.as_str().to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_nonce_token_on_default_src_when_validate_token_then_returns_not_allowed_error() {
        let error = CspOptions::validate_token("default-src", "'nonce-abcd'")
            .expect_err("nonces are not allowed on default-src");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'nonce-abcd'".to_string());
                assert_eq!(directive, "default-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_nonce_without_closing_quote_when_validate_token_then_returns_invalid_nonce() {
        let error = CspOptions::validate_token("script-src", "'nonce-abcd")
            .expect_err("nonce tokens require a closing quote");

        assert_eq!(error, CspOptionsError::InvalidNonce);
    }

    #[test]
    fn given_sha256_with_invalid_character_when_validate_token_then_returns_invalid_hash() {
        let mut value = "A".repeat(43);
        value.push('!');
        let token = format!("'sha256-{value}'");

        let error = CspOptions::validate_token("script-src", &token)
            .expect_err("invalid base64 characters should be rejected");

        assert_eq!(error, CspOptionsError::InvalidHash);
    }

    #[test]
    fn given_disallowed_scheme_when_enforce_scheme_restrictions_then_returns_error() {
        let error = CspOptions::enforce_scheme_restrictions("script-src", "javascript:")
            .expect_err("javascript scheme should be rejected");

        match error {
            CspOptionsError::DisallowedScheme(directive, scheme) => {
                assert_eq!(directive, "script-src".to_string());
                assert_eq!(scheme, "javascript".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_token_wrapped_in_double_quotes_when_validate_token_then_returns_invalid_token() {
        let error = CspOptions::validate_token("script-src", "\"inline\"")
            .expect_err("double-quoted token should be rejected");

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_control_character_token_when_validate_token_then_returns_invalid_token() {
        let token = "'hash\u{0007}'";
        let error = CspOptions::validate_token("script-src", token)
            .expect_err("control characters should be rejected");

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_sha256_token_on_img_src_when_validate_token_then_returns_not_allowed_error() {
        let token = format!("'sha256-{}'", "A".repeat(44));
        let error = CspOptions::validate_token("img-src", &token)
            .expect_err("sha256 hashes require hash-supporting directives");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(returned, directive) => {
                assert_eq!(returned, token);
                assert_eq!(directive, "img-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_sha384_token_on_img_src_when_validate_token_then_returns_not_allowed_error() {
        let token = format!("'sha384-{}'", "A".repeat(64));
        let error = CspOptions::validate_token("img-src", &token)
            .expect_err("sha384 hashes require hash-supporting directives");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(returned, directive) => {
                assert_eq!(returned, token);
                assert_eq!(directive, "img-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_sha512_token_on_img_src_when_validate_token_then_returns_not_allowed_error() {
        let token = format!("'sha512-{}'", "A".repeat(88));
        let error = CspOptions::validate_token("img-src", &token)
            .expect_err("sha512 hashes require hash-supporting directives");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(returned, directive) => {
                assert_eq!(returned, token);
                assert_eq!(directive, "img-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_unsafe_eval_on_style_src_when_validate_token_then_returns_not_allowed_error() {
        let error = CspOptions::validate_token("style-src", "'unsafe-eval'")
            .expect_err("unsafe-eval should be rejected for style-src");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'unsafe-eval'".to_string());
                assert_eq!(directive, "style-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_strict_dynamic_on_style_src_when_validate_token_then_returns_not_allowed_error() {
        let error = CspOptions::validate_token("style-src", "'strict-dynamic'")
            .expect_err("strict-dynamic applies only to script directives");

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'strict-dynamic'".to_string());
                assert_eq!(directive, "style-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_nonce_short_when_validate_token_then_returns_invalid_nonce() {
        let error = CspOptions::validate_token("script-src", "'nonce-short'")
            .expect_err("short nonce values should be rejected");

        assert_eq!(error, CspOptionsError::InvalidNonce);
    }

    #[test]
    fn given_nonce_with_invalid_character_when_validate_token_then_returns_invalid_nonce() {
        let error = CspOptions::validate_token("script-src", "'nonce-AAAAAAAAAAAAAAAAAAAA!A'")
            .expect_err("invalid nonce characters should be rejected");

        assert_eq!(error, CspOptionsError::InvalidNonce);
    }
}

mod utility_helpers {
    use super::*;

    #[test]
    fn given_quoted_input_when_sanitize_token_input_then_returns_trimmed_value() {
        let sanitized = sanitize_token_input("  'token-value'  ".to_string());

        assert_eq!(sanitized, "token-value");
    }

    #[test]
    fn given_existing_token_when_contains_token_then_returns_true() {
        assert!(contains_token("'self' 'nonce-abc'", "'self'"));
        assert!(!contains_token("'self' 'nonce-abc'", "'report-sample'"));
    }

    #[test]
    fn given_newline_when_has_invalid_header_text_then_returns_true() {
        assert!(CspOptions::has_invalid_header_text("value\nmore"));
        assert!(!CspOptions::has_invalid_header_text("single-line"));
    }
}

mod risky_scheme_warnings_single_level {
    use super::*;

    #[test]
    fn given_only_warning_schemes_when_validate_with_warnings_then_emits_warning_severity() {
        let options = CspOptions::new().img_src([CspSource::raw("blob:")]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation should succeed");

        let warning = warnings
            .iter()
            .find(|w| matches!(w.kind, CspOptionsWarningKind::RiskySchemes { .. }))
            .expect("expected risky schemes warning");

        assert!(matches!(warning.severity, CspWarningSeverity::Warning));
    }
}
