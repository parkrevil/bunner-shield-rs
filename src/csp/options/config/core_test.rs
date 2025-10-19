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
    use super::*;

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
