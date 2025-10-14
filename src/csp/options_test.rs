use super::*;
use crate::executor::FeatureOptions;

mod validate {
    use super::*;

    #[test]
    fn given_minimum_directives_when_validate_then_returns_policy() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .base_uri([CspSource::None])
            .frame_ancestors([CspSource::None]);

        options.validate().expect("policy");

        assert!(!options.report_only);
        assert!(options.report_group.is_none());
        assert_eq!(
            options.header_value(),
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn given_uppercase_directive_when_validate_then_returns_error() {
        #[allow(deprecated)]
        let options = CspOptions::new().directive("Default-Src", "'self'");

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidDirectiveName)));
    }

    #[test]
    fn given_report_only_without_group_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_only();

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::ReportOnlyMissingGroup)
        ));
    }

    #[test]
    fn given_invalid_group_when_validate_then_returns_error() {
        let group = CspReportGroup::new("", "https://reports.example.com");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidReportGroup)));
    }

    #[test]
    fn given_valid_nonce_when_validate_then_accepts_directive() {
        let options = CspOptions::new()
            .script_src([CspSource::Nonce(
                "dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".to_string(),
            )])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_invalid_nonce_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .script_src([CspSource::Nonce("@@@@".to_string())])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidNonce)));
    }

    #[test]
    fn given_invalid_hash_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .script_src([CspSource::Hash {
                algorithm: CspHashAlgorithm::Sha256,
                value: "short".to_string(),
            }])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidHash)));
    }

    #[test]
    fn given_control_character_when_validate_then_returns_error() {
        #[allow(deprecated)]
        let options = CspOptions::new().directive("default-src", "'self'\nscript");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidDirectiveToken)
        ));
    }

    #[test]
    fn given_strict_dynamic_without_nonce_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .script_src([CspSource::StrictDynamic])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::StrictDynamicRequiresNonceOrHash)
        ));
    }

    #[test]
    fn given_strict_dynamic_with_unsafe_inline_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .script_src([
                CspSource::StrictDynamic,
                CspSource::UnsafeInline,
                CspSource::Nonce("dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".into()),
            ])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::StrictDynamicConflicts)
        ));
    }

    #[test]
    fn given_strict_dynamic_with_nonce_when_validate_then_accepts() {
        let options = CspOptions::new()
            .script_src([
                CspSource::StrictDynamic,
                CspSource::Nonce("dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".into()),
            ])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_strict_dynamic_in_elem_with_nonce_in_script_when_validate_then_accepts() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src([CspSource::Nonce("dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".into())])
            .script_src_elem([CspSource::StrictDynamic]);

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_nonce_in_img_src_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .img_src([CspSource::Nonce(
                "dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".to_string(),
            )])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, _))
        ));
    }

    #[test]
    fn given_strict_dynamic_in_style_src_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .style_src([CspSource::StrictDynamic])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, _))
        ));
    }

    #[test]
    fn given_script_src_elem_with_strict_dynamic_without_nonce_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .script_src_elem([CspSource::StrictDynamic])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::StrictDynamicRequiresNonceOrHash)
        ));
    }

    #[test]
    fn given_strict_dynamic_conflict_across_directives_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src([
                CspSource::StrictDynamic,
                CspSource::Nonce("dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".into()),
            ])
            .script_src_elem([CspSource::UnsafeInline]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::StrictDynamicConflicts)
        ));
    }

    #[test]
    fn given_none_with_other_sources_when_validate_then_returns_error() {
        let options = CspOptions::new().default_src([CspSource::None, CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::ConflictingNoneToken)));
    }

    #[test]
    fn given_upgrade_insecure_requests_when_validate_then_accepts_flag_directive() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .upgrade_insecure_requests();

        let result = options.validate();

        assert!(result.is_ok());
        assert_eq!(
            options.header_value(),
            "default-src 'self'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn given_sandbox_invalid_token_when_validate_then_returns_error() {
        let mut options = CspOptions::new().default_src([CspSource::SelfKeyword]);
        options
            .directives
            .push(("sandbox".to_string(), "allow-invalid".to_string()));

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidSandboxToken(_))
        ));
    }

    #[test]
    fn given_report_group_without_report_to_when_validate_then_returns_error() {
        let mut options = CspOptions::new().default_src([CspSource::SelfKeyword]);
        options.report_group = Some(CspReportGroup::new(
            "default",
            "https://reports.example.com",
        ));

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::MissingReportToDirective)
        ));
    }

    #[test]
    fn given_report_group_with_mismatched_report_to_when_validate_then_returns_error() {
        let group = CspReportGroup::new("default", "https://reports.example.com");
        let mut options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        if let Some((_, value)) = options
            .directives
            .iter_mut()
            .find(|(name, _)| name == "report-to")
        {
            *value = "other".to_string();
        }

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::ReportToGroupMismatch)
        ));
    }

    #[test]
    fn given_report_group_with_non_https_endpoint_when_validate_then_returns_error() {
        let group = CspReportGroup::new("default", "http://reports.example.com");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        let result = options.validate();

        assert!(matches!(result, Err(CspOptionsError::InvalidReportGroup)));
    }

    #[test]
    fn given_report_group_with_additional_endpoint_when_validate_then_accepts() {
        let group = CspReportGroup::new("default", "https://reports.example.com")
            .add_endpoint(CspReportEndpoint::new("https://backup.example.com"));
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        let result = options.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn given_report_to_with_multiple_values_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_to("group another");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::MultipleReportToValues)
        ));
    }

    #[test]
    fn given_report_to_with_invalid_characters_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_to("group!");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidReportToToken(token)) if token == "group!"
        ));
    }

    #[test]
    fn given_unsafe_inline_in_img_src_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .img_src([CspSource::UnsafeInline])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, directive)) if directive == "img-src"
        ));
    }

    #[test]
    fn given_unsafe_inline_in_style_src_when_validate_then_accepts() {
        let options = CspOptions::new()
            .style_src([CspSource::UnsafeInline])
            .default_src([CspSource::SelfKeyword]);

        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_unsafe_eval_in_style_src_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .style_src([CspSource::UnsafeEval])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, directive)) if directive == "style-src"
        ));
    }

    #[test]
    fn given_unsafe_hashes_in_script_src_elem_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src_elem([CspSource::UnsafeHashes]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, directive))
                if directive == "script-src-elem"
        ));
    }

    #[test]
    fn given_unsafe_hashes_in_style_src_attr_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src_attr([CspSource::UnsafeHashes]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, directive))
                if directive == "style-src-attr"
        ));
    }

    #[test]
    fn given_report_sample_in_img_src_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .img_src([CspSource::ReportSample])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::TokenNotAllowedForDirective(_, directive)) if directive == "img-src"
        ));
    }

    #[test]
    fn given_invalid_scheme_source_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::raw("1https:")])
            .base_uri([CspSource::None])
            .frame_ancestors([CspSource::None]);

        let result = options.validate();

        assert!(
            matches!(result, Err(CspOptionsError::InvalidSourceExpression(expr)) if expr == "1https:")
        );
    }

    #[test]
    fn given_invalid_host_source_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .connect_src([CspSource::raw("exa@mple.com")])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidSourceExpression(expr)) if expr == "exa@mple.com"
        ));
    }

    #[test]
    fn given_javascript_scheme_when_validate_then_returns_error() {
        let options = CspOptions::new().default_src([CspSource::raw("javascript:")]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::DisallowedScheme(directive, scheme))
                if directive == "default-src" && scheme == "javascript"
        ));
    }

    #[test]
    fn given_host_with_port_wildcard_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .connect_src([CspSource::raw("https://api.example.com:*")])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::PortWildcardUnsupported(expr)) if expr == "https://api.example.com:*"
        ));
    }

    #[test]
    fn given_invalid_wildcard_source_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .frame_src([CspSource::raw("*.*.example.com")])
            .default_src([CspSource::SelfKeyword]);

        let result = options.validate();

        assert!(
            matches!(result, Err(CspOptionsError::InvalidSourceExpression(expr)) if expr == "*.*.example.com")
        );
    }

    #[test]
    fn given_reporting_endpoint_with_http_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .reporting_endpoint("default", "http://reports.example.com");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::InvalidReportingEndpointUrl(url)) if url == "http://reports.example.com"
        ));
    }

    #[test]
    fn given_duplicate_reporting_endpoint_names_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .reporting_endpoint("csp", "https://reports.example.com")
            .reporting_endpoint("CSP", "https://backup.example.com");

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::DuplicateReportingEndpoint(name)) if name == "CSP"
        ));
    }

    #[test]
    fn given_missing_worker_fallback_when_validate_with_warnings_then_reports_warning() {
        let options = CspOptions::new().base_uri([CspSource::SelfKeyword]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert_eq!(
            warnings,
            vec![CspOptionsWarning::critical(
                CspOptionsWarningKind::MissingWorkerSrcFallback,
            )]
        );
        assert!(options.validate().is_ok());
    }

    #[test]
    fn given_report_only_with_frame_ancestors_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .frame_ancestors([CspSource::None])
            .report_only()
            .report_group(CspReportGroup::new(
                "default",
                "https://reports.example.com",
            ));

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::warning(
            CspOptionsWarningKind::ReportOnlyFrameAncestorsIgnored,
        )));
    }

    #[test]
    fn given_strict_dynamic_with_hosts_when_validate_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src([
                CspSource::StrictDynamic,
                CspSource::Nonce("dGVzdE5vbmNlVmFsdWVTYWZlMTIzNDU=".into()),
                CspSource::host("https://cdn.example.com"),
            ]);

        let result = options.validate();

        assert!(matches!(
            result,
            Err(CspOptionsError::StrictDynamicHostSourceConflict)
        ));
    }

    #[test]
    fn given_report_group_with_large_max_age_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(
                CspReportGroup::new("default", "https://reports.example.com")
                    .with_max_age(40_000_000),
            );

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::warning(
            CspOptionsWarningKind::ReportGroupMaxAgeTooHigh {
                max_age: 40_000_000
            },
        )));
    }

    #[test]
    fn given_upgrade_insecure_requests_without_block_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .upgrade_insecure_requests();

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::warning(
            CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
        )));
    }

    #[test]
    fn given_block_all_mixed_content_without_upgrade_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .block_all_mixed_content();

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::warning(
            CspOptionsWarningKind::BlockAllMixedContentWithoutUpgradeInsecureRequests,
        )));
    }

    #[test]
    fn given_reporting_endpoints_without_report_to_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .reporting_endpoint("default", "https://reports.example.com");

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::warning(
            CspOptionsWarningKind::ReportingEndpointsWithoutDirective,
        )));
    }

    #[test]
    fn given_worker_fallback_star_default_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new().default_src([CspSource::raw("*")]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert_eq!(
            warnings,
            vec![CspOptionsWarning::warning(
                CspOptionsWarningKind::WeakWorkerSrcFallback,
            )]
        );
    }

    #[test]
    fn given_risky_scheme_when_validate_with_warnings_then_warns() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src([CspSource::raw("data:")]);

        let warnings = options
            .validate_with_warnings()
            .expect("validation succeeds");

        assert!(warnings.contains(&CspOptionsWarning::critical(
            CspOptionsWarningKind::RiskySchemes {
                directive: "script-src".to_string(),
                schemes: vec!["data".to_string()],
            },
        )));
    }
}

mod whitelist {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn whitelist_matches_enum_variants() {
        let mut seen = HashSet::new();

        for directive in CspDirective::ALL {
            let name = directive.as_str();

            assert!(
                CspOptions::is_valid_directive_name(name),
                "enum-derived directive `{name}` must be accepted"
            );

            assert!(
                seen.insert(name),
                "directive `{name}` appears multiple times in whitelist"
            );
        }

        assert_eq!(
            seen.len(),
            CspDirective::ALL.len(),
            "whitelist should contain every enum variant exactly once"
        );

        for name in [
            "child-src",
            "plugin-types",
            "prefetch-src",
            "report-uri",
            "bogus-directive",
        ] {
            assert!(
                !CspOptions::is_valid_directive_name(name),
                "deprecated or unknown directive `{name}` must be rejected"
            );
        }
    }
}

mod helpers {
    use super::*;

    #[test]
    fn given_nonce_helper_when_header_value_then_includes_trimmed_token() {
        let options = CspOptions::new()
            .script_src_nonce(" 'dGVzdE5vbmNlVmFsdWU=' ")
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'nonce-dGVzdE5vbmNlVmFsdWU='; default-src 'self'"
        );
    }

    #[test]
    fn given_duplicate_nonce_helper_when_header_value_then_deduplicates_token() {
        let options = CspOptions::new()
            .script_src_nonce("value")
            .script_src_nonce("value")
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'nonce-value'; default-src 'self'"
        );
    }

    #[test]
    fn given_hash_helper_when_header_value_then_includes_prefixed_token() {
        let options = CspOptions::new()
            .script_src_hash(CspHashAlgorithm::Sha384, "abc==")
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'sha384-abc=='; default-src 'self'"
        );
    }

    #[test]
    fn given_strict_dynamic_helper_when_header_value_then_adds_once() {
        let options = CspOptions::new()
            .enable_strict_dynamic()
            .enable_strict_dynamic()
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'strict-dynamic'; default-src 'self'"
        );
    }

    #[test]
    fn given_trusted_types_helper_when_header_value_then_sets_directive() {
        let options = CspOptions::new()
            .require_trusted_types_for_scripts()
            .require_trusted_types_for_scripts()
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "require-trusted-types-for 'script'; default-src 'self'"
        );
    }

    #[test]
    fn given_typed_helper_when_header_value_then_formats_sources() {
        let options = CspOptions::new()
            .script_src([
                CspSource::SelfKeyword,
                CspSource::scheme("https"),
                CspSource::host("https://cdn.example.com"),
            ])
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'self' https: https://cdn.example.com; default-src 'self'"
        );
    }

    #[test]
    fn given_script_src_elem_helper_when_header_value_then_formats_sources() {
        let options = CspOptions::new()
            .script_src_elem([CspSource::SelfKeyword])
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src-elem 'self'; default-src 'self'"
        );
    }

    #[test]
    fn given_style_src_attr_helper_when_header_value_then_formats_sources() {
        let options = CspOptions::new()
            .style_src_attr([CspSource::SelfKeyword])
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "style-src-attr 'self'; default-src 'self'"
        );
    }

    #[test]
    fn given_trusted_types_helper_when_header_value_then_formats_policies() {
        let options = CspOptions::new()
            .trusted_types_tokens([
                TrustedTypesToken::policy(TrustedTypesPolicy::new("default").expect("policy")),
                TrustedTypesToken::allow_duplicates(),
            ])
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "trusted-types default 'allow-duplicates'; default-src 'self'"
        );
    }

    #[test]
    fn given_upgrade_insecure_requests_helper_when_header_value_then_adds_flag() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .upgrade_insecure_requests();

        assert_eq!(
            options.header_value(),
            "default-src 'self'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn given_block_all_mixed_content_helper_when_header_value_then_adds_flag() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .block_all_mixed_content();

        assert_eq!(
            options.header_value(),
            "default-src 'self'; block-all-mixed-content"
        );
    }

    #[test]
    fn given_duplicate_sources_when_header_value_then_deduplicates_entries() {
        let options = CspOptions::new()
            .script_src([
                CspSource::SelfKeyword,
                CspSource::SelfKeyword,
                CspSource::host("https://cdn.example.com"),
                CspSource::host("https://cdn.example.com"),
            ])
            .default_src([CspSource::SelfKeyword]);

        assert_eq!(
            options.header_value(),
            "script-src 'self' https://cdn.example.com; default-src 'self'"
        );
    }

    #[test]
    fn given_report_to_helper_when_header_value_then_sets_directive() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_to("default");

        assert_eq!(
            options.header_value(),
            "default-src 'self'; report-to default"
        );
    }

    #[test]
    fn given_sandbox_helper_when_header_value_then_adds_flag_directive() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .sandbox();

        assert_eq!(options.header_value(), "default-src 'self'; sandbox");
    }

    #[test]
    fn given_sandbox_with_helper_when_header_value_then_formats_tokens_once() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .sandbox_with([
                SandboxToken::AllowScripts,
                SandboxToken::AllowSameOrigin,
                SandboxToken::AllowScripts,
            ]);

        assert_eq!(
            options.header_value(),
            "default-src 'self'; sandbox allow-scripts allow-same-origin"
        );
    }

    #[test]
    fn given_manual_sandbox_directive_when_header_value_then_preserves_tokens() {
        #[allow(deprecated)]
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .directive("sandbox", "allow-scripts allow-same-origin");

        assert_eq!(
            options.header_value(),
            "default-src 'self'; sandbox allow-scripts allow-same-origin"
        );
    }

    #[test]
    fn given_nonce_manager_when_issue_then_applies_to_script_src() {
        let manager = CspNonceManager::new();
        let nonce = manager.issue();
        let header_value = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src_with_nonce(nonce.clone())
            .header_value();

        assert!(header_value.contains("script-src 'nonce-"));
        assert!(nonce.header_value().starts_with("'nonce-"));
    }

    #[test]
    fn given_nonce_manager_with_size_zero_when_issue_then_returns_error() {
        let result = CspNonceManager::with_size(0);

        assert!(matches!(result, Err(CspNonceManagerError::InvalidLength)));
    }
}

mod composition {
    use super::*;

    #[test]
    fn given_add_source_when_header_value_then_preserves_unique_tokens() {
        let options = CspOptions::new()
            .script_src([CspSource::SelfKeyword])
            .add_source(CspDirective::ScriptSrc, CspSource::scheme("https"))
            .add_source(CspDirective::ScriptSrc, CspSource::scheme("https"));

        assert_eq!(options.header_value(), "script-src 'self' https:");
    }

    #[test]
    fn given_merge_with_conflicting_report_to_when_merge_then_keeps_existing_group() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_to("primary");

        let other = CspOptions::new().report_to("secondary");

        let merged = options.merge(&other);

        assert_eq!(
            merged.directive_value(CspDirective::ReportTo.as_str()),
            Some("primary")
        );
    }

    #[test]
    fn given_merge_with_reporting_endpoints_when_merge_then_deduplicates_and_sets_report_only() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .reporting_endpoint("primary", "https://reports.example.com");

        let other = CspOptions::new()
            .reporting_endpoint("PRIMARY", "https://duplicate.example.com")
            .reporting_endpoint("backup", "https://backup.example.com")
            .report_only();

        let merged = options.merge(&other);

        let endpoint_names: Vec<_> = merged
            .reporting_endpoints
            .iter()
            .map(|endpoint| endpoint.name())
            .collect();

        assert_eq!(endpoint_names, vec!["primary", "backup"]);
        assert!(merged.report_only);
    }

    #[test]
    fn given_merge_with_report_group_when_merge_then_combines_endpoints() {
        let group = CspReportGroup::new("default", "https://reports.example.com");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        let merged = options.merge(
            &CspOptions::new().report_group(
                CspReportGroup::new("default", "https://reports.example.com")
                    .with_max_age(60)
                    .include_subdomains()
                    .add_endpoint(CspReportEndpoint::new("https://backup.example.com")),
            ),
        );

        let merged_group = merged.report_group.as_ref().expect("report group");
        assert_eq!(merged_group.max_age(), 60);
        assert!(merged_group.includes_subdomains());
        let urls: Vec<_> = merged_group
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.url())
            .collect();
        assert_eq!(
            urls,
            vec!["https://reports.example.com", "https://backup.example.com",]
        );
    }
}

mod report_group {
    use super::*;

    #[test]
    fn given_valid_group_when_header_value_then_returns_serialized_json() {
        let group = CspReportGroup::new("default", "https://reports.example.com");

        let header_value = group.header_value();

        assert_eq!(
            header_value,
            "{\"group\":\"default\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://reports.example.com\"}]}"
        );
    }

    #[test]
    fn given_report_group_when_header_value_then_sets_report_to_directive() {
        let group = CspReportGroup::new("default", "https://reports.example.com");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_group(group);

        assert_eq!(
            options.header_value(),
            "default-src 'self'; report-to default"
        );
    }

    #[test]
    fn given_group_with_multiple_endpoints_when_header_value_then_serializes_all() {
        let group = CspReportGroup::new("default", "https://reports.example.com")
            .with_max_age(300)
            .include_subdomains()
            .add_endpoint(
                CspReportEndpoint::new("https://backup.example.com")
                    .with_priority(10)
                    .with_weight(2),
            );

        assert_eq!(
            group.header_value(),
            "{\"group\":\"default\",\"max_age\":300,\"include_subdomains\":true,\"endpoints\":[{\"url\":\"https://reports.example.com\"},{\"url\":\"https://backup.example.com\",\"priority\":10,\"weight\":2}]}"
        );
    }
}

mod trusted_types {
    use super::*;

    #[test]
    fn given_valid_policy_name_when_new_then_returns_policy() {
        let policy = TrustedTypesPolicy::new("default-policy").expect("policy");

        assert_eq!(policy.as_str(), "default-policy");
    }

    #[test]
    fn given_invalid_policy_name_when_new_then_returns_error() {
        let result = TrustedTypesPolicy::new("1invalid");

        assert!(matches!(
            result,
            Err(TrustedTypesPolicyError::InvalidName(name)) if name == "1invalid"
        ));
    }

    #[test]
    fn given_empty_policy_name_when_new_then_returns_error() {
        let result = TrustedTypesPolicy::new("");

        assert!(matches!(result, Err(TrustedTypesPolicyError::Empty)));
    }
}
