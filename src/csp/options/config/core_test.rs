use super::*;

mod header_and_merge {
    use super::*;

    #[test]
    fn given_default_src_when_header_value_then_renders_single_directive() {
        let options = CspOptions::new().default_src([CspSource::Wildcard]);
        assert_eq!(options.header_value(), "default-src *");
    }

    #[test]
    fn given_merge_with_report_to_when_missing_then_copies_group() {
        let base = CspOptions::new().default_src([CspSource::SelfKeyword]);
        let overlay = CspOptions::new().report_to("primary");
        let merged = base.merge(&overlay);
        assert!(merged.header_value().contains("report-to primary"));
    }
}

mod stable_serialization {
    use super::*;

    #[test]
    fn given_directives_added_in_any_order_when_header_value_then_returns_sorted_output() {
        let option_a = CspOptions::new()
            .script_src(|script| script.sources([CspSource::SelfKeyword]))
            .default_src([CspSource::Wildcard]);

        let option_b = CspOptions::new()
            .default_src([CspSource::Wildcard])
            .script_src(|script| script.sources([CspSource::SelfKeyword]));

        let expected = "default-src *; script-src 'self'";

        assert_eq!(option_a.header_value(), expected);
        assert_eq!(option_b.header_value(), expected);
    }

    #[test]
    fn given_tokens_added_in_any_order_when_header_value_then_sorts_tokens() {
        let header = CspOptions::new()
            .script_src(|script| script.nonce("bbb").strict_dynamic().nonce("aaa"))
            .header_value();

        assert!(
            header.contains("script-src 'nonce-aaa' 'nonce-bbb' 'strict-dynamic'"),
            "unexpected header value: {}",
            header
        );
    }
}

mod runtime_nonce_integration {
    use super::*;

    #[test]
    fn given_runtime_nonce_configuration_when_render_then_substitutes_placeholder() {
        let options = CspOptions::new()
            .runtime_nonce_manager(CspNonceManager::with_size(18).expect("nonce size"))
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| script.runtime_nonce().strict_dynamic());

        let placeholder_header = options.header_value();
        let config = options.runtime_nonce_config().expect("config exists");

        let placeholder_token = config
            .directives()
            .find(|(name, _)| name.as_str() == "script-src")
            .map(|(_, token)| token.clone())
            .expect("placeholder token for script-src");
        assert!(placeholder_header.contains(&placeholder_token));

        let rendered = options.render_with_runtime_nonce("dynamic-nonce-value");
        assert!(rendered.contains("'nonce-dynamic-nonce-value'"));
        assert!(!rendered.contains(&placeholder_token));
    }
}

mod directive_helpers_and_validation {
    mod report_to_merge_strategy {
        use super::*;

        #[test]
        fn given_first_wins_when_merge_then_keeps_initial_group() {
            let base = CspOptions::new().report_to("grpA");
            let other = CspOptions::new().report_to("grpB");

            let merged = base.clone().merge(&other);
            assert_eq!(
                merged
                    .directive_value(CspDirective::ReportTo.as_str())
                    .unwrap(),
                "grpA"
            );
        }

        #[test]
        fn given_last_wins_when_merge_then_overwrites_group() {
            let base = CspOptions::new()
                .report_to("grpA")
                .report_to_merge_strategy(ReportToMergeStrategy::LastWins);
            let other = CspOptions::new().report_to("grpB");

            let merged = base.merge(&other);
            assert_eq!(
                merged
                    .directive_value(CspDirective::ReportTo.as_str())
                    .unwrap(),
                "grpB"
            );
        }

        #[test]
        fn given_union_when_merge_then_joins_unique_tokens() {
            let base = CspOptions::new()
                .report_to("grpA grpB")
                .report_to_merge_strategy(ReportToMergeStrategy::Union);
            let other = CspOptions::new().report_to("grpB grpC");

            let merged = base.merge(&other);
            let value = merged
                .directive_value(CspDirective::ReportTo.as_str())
                .unwrap();
            // Order-preserving unique union: grpA grpB grpC
            assert_eq!(value, "grpA grpB grpC");
        }
    }
    use super::*;

    #[test]
    fn given_invalid_directive_name_when_validate_then_returns_error() {
        let mut options = CspOptions::new();
        options.set_directive("bogus", "value");
        let error = options
            .validate_with_warnings()
            .expect_err("expected invalid directive name");
        assert_eq!(error, CspOptionsError::InvalidDirectiveName);
    }

    mod risky_scheme_warnings {
        use super::*;

        fn find_risky_warning<'a>(
            warnings: &'a [CspOptionsWarning],
            directive: &str,
        ) -> Option<&'a CspOptionsWarning> {
            warnings.iter().find(|w| match &w.kind {
                CspOptionsWarningKind::RiskySchemes { directive: d, .. } => d == directive,
                _ => false,
            })
        }

        #[test]
        fn given_data_in_script_like_directives_then_emits_critical() {
            let options = CspOptions::new()
                .script_src(|s| s.sources([CspSource::scheme("data")]))
                .object_src([CspSource::scheme("data")]);
            let warnings = options.validate_with_warnings().expect("ok");

            let script_warn = find_risky_warning(&warnings, "script-src").expect("warn");
            assert_eq!(script_warn.severity, CspWarningSeverity::Critical);

            let object_warn = find_risky_warning(&warnings, "object-src").expect("warn");
            assert_eq!(object_warn.severity, CspWarningSeverity::Critical);
        }

        #[test]
        fn given_data_in_img_then_emits_warning_not_critical() {
            let options = CspOptions::new().img_src([CspSource::scheme("data")]);
            let warnings = options.validate_with_warnings().expect("ok");
            let img_warn = find_risky_warning(&warnings, "img-src").expect("warn");
            assert_eq!(img_warn.severity, CspWarningSeverity::Warning);
        }

        #[test]
        fn given_blob_in_font_then_emits_info() {
            let options = CspOptions::new().font_src([CspSource::scheme("blob")]);
            let warnings = options.validate_with_warnings().expect("ok");
            let font_warn = find_risky_warning(&warnings, "font-src").expect("warn");
            assert_eq!(font_warn.severity, CspWarningSeverity::Info);
        }
    }
}
