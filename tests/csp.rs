use bunner_shield_rs::{
    CspNonceManager, CspOptions, CspOptionsError, CspSource, Shield, ShieldError,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn with_csp(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Content-Security-Policy".to_string(), value.to_string());
    headers
}

mod success {
    use super::*;
    use bunner_shield_rs::{CspHashAlgorithm, SandboxToken, TrustedTypesPolicy, TrustedTypesToken};
    use std::collections::HashMap;

    fn parse_csp_header(header: &str) -> HashMap<String, Vec<String>> {
        let mut directives = HashMap::new();

        for part in header.split(';') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut segments = trimmed.split_whitespace();
            let directive = segments
                .next()
                .unwrap_or_else(|| panic!("missing directive name in `{trimmed}`"));
            let mut tokens: Vec<String> = segments.map(|token| token.to_string()).collect();
            tokens.sort();

            directives.insert(directive.to_string(), tokens);
        }

        directives
    }

    fn assert_directive_tokens(
        directives: &HashMap<String, Vec<String>>,
        name: &str,
        expected: &[&str],
    ) {
        let mut expected_tokens: Vec<String> =
            expected.iter().map(|token| token.to_string()).collect();
        expected_tokens.sort();

        let actual = directives
            .get(name)
            .unwrap_or_else(|| panic!("missing directive `{name}`"));

        assert_eq!(actual, &expected_tokens, "directive `{name}` mismatch");
    }

    #[test]
    fn given_minimal_policy_when_secure_then_emits_expected_directives() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .base_uri([CspSource::None])
            .frame_ancestors([CspSource::None]);
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Content-Security-Policy").map(String::as_str),
            Some("default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        );
    }

    #[test]
    fn given_repeated_sources_when_secure_then_deduplicates_tokens() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .img_src([
                CspSource::SelfKeyword,
                CspSource::SelfKeyword,
                CspSource::SelfKeyword,
            ]);
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Content-Security-Policy").map(String::as_str),
            Some("default-src 'self'; img-src 'self'")
        );
    }

    #[test]
    fn given_nonce_manager_when_secure_then_injects_nonce_into_script_src() {
        let nonce = CspNonceManager::new().issue();
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| script.nonce_value(nonce.clone()));
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let nonce_value = format!("'nonce-{}'", nonce.into_inner());
        let header = result
            .get("Content-Security-Policy")
            .map(String::to_string)
            .expect("csp header");

        assert!(header.contains("script-src"));
        assert!(header.contains(&nonce_value));
    }

    #[test]
    fn given_trusted_types_none_when_secure_then_overrides_existing_tokens() {
        let policy = TrustedTypesPolicy::new("frontend").expect("policy");

        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .trusted_types_policies([policy.clone(), policy])
            .trusted_types_none();
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");
        let header = result.get("Content-Security-Policy").expect("csp header");
        let directives = parse_csp_header(header);

        assert_directive_tokens(&directives, "trusted-types", &["'none'"]);
    }

    #[test]
    fn given_script_src_nonce_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "a".repeat(22);
        let hash = "B".repeat(44);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .nonce(format!("  {nonce}  "))
                    .hash(CspHashAlgorithm::Sha256, hash.clone())
                    .strict_dynamic()
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src",
            &[
                &format!("'nonce-{nonce}'"),
                &format!("'sha256-{hash}'"),
                "'strict-dynamic'",
            ],
        );
    }

    #[test]
    fn given_script_src_elem_nonce_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "b".repeat(22);
        let hash = "C".repeat(64);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .elem_nonce(nonce.clone())
                    .elem_hash(CspHashAlgorithm::Sha384, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src-elem",
            &[&format!("'nonce-{nonce}'"), &format!("'sha384-{hash}'")],
        );
    }

    #[test]
    fn given_script_src_attr_nonce_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "c".repeat(22);
        let hash = "D".repeat(88);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .attr([CspSource::SelfKeyword])
                    .attr_nonce(nonce.clone())
                    .attr_hash(CspHashAlgorithm::Sha512, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src-attr",
            &[
                "'self'",
                &format!("'nonce-{nonce}'"),
                &format!("'sha512-{hash}'"),
            ],
        );
    }

    #[test]
    fn given_style_src_inline_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "d".repeat(22);
        let hash = "E".repeat(64);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src(|style| {
                style
                    .sources([
                        CspSource::SelfKeyword,
                        CspSource::UnsafeInline,
                        CspSource::UnsafeHashes,
                    ])
                    .nonce(nonce.clone())
                    .hash(CspHashAlgorithm::Sha384, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "style-src",
            &[
                "'self'",
                "'unsafe-inline'",
                "'unsafe-hashes'",
                &format!("'nonce-{nonce}'"),
                &format!("'sha384-{hash}'"),
            ],
        );
    }

    #[test]
    fn given_style_src_elem_nonce_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "e".repeat(22);
        let hash = "F".repeat(44);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src(|style| {
                style
                    .elem([CspSource::SelfKeyword])
                    .elem_nonce(nonce.clone())
                    .elem_hash(CspHashAlgorithm::Sha256, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "style-src-elem",
            &[
                "'self'",
                &format!("'nonce-{nonce}'"),
                &format!("'sha256-{hash}'"),
            ],
        );
    }

    #[test]
    fn given_style_src_attr_nonce_and_hash_when_secure_then_emits_expected_tokens() {
        let nonce = "f".repeat(22);
        let hash = "G".repeat(88);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src(|style| {
                style
                    .attr([CspSource::SelfKeyword])
                    .attr_nonce(nonce.clone())
                    .attr_hash(CspHashAlgorithm::Sha512, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "style-src-attr",
            &[
                "'self'",
                &format!("'nonce-{nonce}'"),
                &format!("'sha512-{hash}'"),
            ],
        );
    }

    #[test]
    fn given_script_src_with_unsafe_hashes_and_hash_when_secure_then_emits_expected_tokens() {
        let hash = "R".repeat(44);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .sources([CspSource::UnsafeHashes])
                    .hash(CspHashAlgorithm::Sha256, hash.clone())
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src",
            &["'unsafe-hashes'", &format!("'sha256-{hash}'")],
        );
    }

    #[test]
    fn given_trusted_types_tokens_when_secure_then_deduplicates_values() {
        let main = TrustedTypesPolicy::new("appMain").expect("policy");
        let backup = TrustedTypesPolicy::new("appBackup").expect("policy");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .trusted_types_tokens([
                TrustedTypesToken::from(main.clone()),
                TrustedTypesToken::from(main),
                TrustedTypesToken::from(backup),
                TrustedTypesToken::allow_duplicates(),
            ])
            .require_trusted_types_for_scripts();
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "trusted-types",
            &["'allow-duplicates'", "appBackup", "appMain"],
        );
        assert_directive_tokens(&directives, "require-trusted-types-for", &["'script'"]);
    }

    #[test]
    fn given_trusted_types_with_nonce_and_hash_when_secure_then_preserves_all_directives() {
        let nonce = "p".repeat(22);
        let hash = "Q".repeat(44);
        let ui_primary = TrustedTypesPolicy::new("uiPrimary").expect("policy");
        let ui_audit = TrustedTypesPolicy::new("uiAudit").expect("policy");

        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .nonce(nonce.clone())
                    .hash(CspHashAlgorithm::Sha256, hash.clone())
            })
            .trusted_types_tokens([
                TrustedTypesToken::from(ui_primary.clone()),
                TrustedTypesToken::from(ui_audit.clone()),
            ])
            .require_trusted_types_for_scripts();
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src",
            &[&format!("'nonce-{nonce}'"), &format!("'sha256-{hash}'")],
        );
        assert_directive_tokens(
            &directives,
            "trusted-types",
            &[ui_audit.as_str(), ui_primary.as_str()],
        );
        assert_directive_tokens(&directives, "require-trusted-types-for", &["'script'"]);
    }

    #[test]
    fn given_trusted_types_none_after_tokens_when_secure_then_resets_directive() {
        let main = TrustedTypesPolicy::new("mainPolicy").expect("policy");
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .trusted_types_policies([main])
            .trusted_types_none();
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "trusted-types", &["'none'"]);
    }

    #[test]
    fn given_report_to_merge_when_secure_then_preserves_first_group() {
        let base = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .report_to("primary");
        let overlay = CspOptions::new().report_to("secondary");
        let options = base.merge(&overlay);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "report-to", &["primary"]);
    }

    #[test]
    fn given_img_src_host_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .img_src([
                CspSource::host("cdn.example.com"),
                CspSource::scheme("https"),
            ]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "img-src", &["cdn.example.com", "https:"]);
    }

    #[test]
    fn given_font_src_host_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .font_src([CspSource::host("fonts.example.com")]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "font-src", &["fonts.example.com"]);
    }

    #[test]
    fn given_frame_src_host_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .frame_src([CspSource::host("frames.example.com")]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "frame-src", &["frames.example.com"]);
    }

    #[test]
    fn given_media_src_host_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .media_src([CspSource::host("media.example.com")]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "media-src", &["media.example.com"]);
    }

    #[test]
    fn given_manifest_src_self_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .manifest_src([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "manifest-src", &["'self'"]);
    }

    #[test]
    fn given_object_src_self_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .object_src([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "object-src", &["'self'"]);
    }

    #[test]
    fn given_base_uri_self_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .base_uri([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "base-uri", &["'self'"]);
    }

    #[test]
    fn given_form_action_self_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .form_action([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "form-action", &["'self'"]);
    }

    #[test]
    fn given_frame_ancestors_none_when_secure_then_sets_expected_sources() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .frame_ancestors([CspSource::None]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "frame-ancestors", &["'none'"]);
    }

    #[test]
    fn given_sandbox_tokens_when_secure_then_deduplicates_entries() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .sandbox_with([
                SandboxToken::AllowScripts,
                SandboxToken::AllowScripts,
                SandboxToken::AllowForms,
            ]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "sandbox", &["allow-forms", "allow-scripts"]);
    }

    #[test]
    fn given_upgrade_insecure_requests_when_secure_then_sets_flag_directive() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .upgrade_insecure_requests();
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "upgrade-insecure-requests", &[]);
    }

    #[test]
    fn given_block_all_mixed_content_when_secure_then_sets_flag_directive() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .block_all_mixed_content();
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "block-all-mixed-content", &[]);
    }

    #[test]
    fn given_worker_src_when_secure_then_uses_configured_scheme() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .worker_src([CspSource::scheme("https")]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "worker-src", &["https:"]);
    }

    #[test]
    fn given_navigate_to_when_secure_then_sets_expected_destinations() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .navigate_to([
                CspSource::SelfKeyword,
                CspSource::host("payments.example.com"),
            ]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "navigate-to",
            &["'self'", "payments.example.com"],
        );
    }

    #[test]
    fn given_connect_src_merge_when_secure_then_combines_sources() {
        let base = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .connect_src([CspSource::SelfKeyword]);
        let overlay = CspOptions::new()
            .connect_src([CspSource::scheme("wss"), CspSource::host("api.example.com")]);
        let options = base.merge(&overlay);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "connect-src",
            &["'self'", "api.example.com", "wss:"],
        );
    }

    #[test]
    fn given_script_src_wasm_unsafe_eval_when_secure_then_includes_token() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script.sources([CspSource::SelfKeyword, CspSource::WasmUnsafeEval])
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "script-src", &["'self'", "'wasm-unsafe-eval'"]);
    }

    #[test]
    fn given_strict_dynamic_with_wasm_unsafe_eval_when_secure_then_emits_expected_tokens() {
        let nonce = "n".repeat(22);
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .script_src(|script| {
                script
                    .sources([CspSource::WasmUnsafeEval])
                    .nonce(nonce.clone())
                    .strict_dynamic()
            });
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(
            &directives,
            "script-src",
            &[
                &format!("'nonce-{nonce}'"),
                "'strict-dynamic'",
                "'wasm-unsafe-eval'",
            ],
        );
    }

    #[test]
    fn given_style_src_report_sample_when_secure_then_includes_token() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src(|style| style.sources([CspSource::SelfKeyword, CspSource::ReportSample]));
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "style-src", &["'report-sample'", "'self'"]);
    }

    #[test]
    fn given_wildcard_source_when_secure_then_emits_asterisk() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .connect_src([CspSource::Wildcard]);
        let shield = Shield::new().csp(options).expect("feature");

        let header = shield
            .secure(empty_headers())
            .expect("secure")
            .get("Content-Security-Policy")
            .cloned()
            .expect("csp header");
        let directives = parse_csp_header(&header);

        assert_directive_tokens(&directives, "connect-src", &["*"]);
    }
}

mod edge {
    use super::*;
    use bunner_shield_rs::CspDirective;

    fn assert_csp_directives(actual: &str, expected: &[&str]) {
        let mut actual_tokens: Vec<_> = actual
            .split(';')
            .map(|directive| directive.trim())
            .filter(|directive| !directive.is_empty())
            .collect();
        let mut expected_tokens: Vec<_> = expected.to_vec();

        actual_tokens.sort_unstable();
        expected_tokens.sort_unstable();

        assert_eq!(actual_tokens, expected_tokens);
    }

    #[test]
    fn given_existing_header_with_lowercase_key_when_secure_then_overwrites_case_insensitively() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .frame_ancestors([CspSource::None]);
        let shield = Shield::new().csp(options).expect("feature");

        let mut headers = HashMap::new();
        headers.insert(
            "content-security-policy".to_string(),
            "default-src *".to_string(),
        );

        let result = shield.secure(headers).expect("secure");
        let header = result.get("Content-Security-Policy").expect("csp header");

        assert_csp_directives(header, &["default-src 'self'", "frame-ancestors 'none'"]);
        assert!(!result.contains_key("content-security-policy"));
    }
    #[test]
    fn given_existing_header_when_secure_then_overwrites_with_new_policy() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .style_src(|style| style.sources([CspSource::SelfKeyword]));
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield
            .secure(with_csp("default-src 'unsafe-inline'"))
            .expect("secure");

        let header = result.get("Content-Security-Policy").expect("csp header");

        assert_csp_directives(header, &["default-src 'self'", "style-src 'self'"]);
    }

    #[test]
    fn given_unrelated_headers_when_secure_then_preserves_them() {
        let options = CspOptions::new().default_src([CspSource::SelfKeyword]);
        let shield = Shield::new().csp(options).expect("feature");

        let mut headers = with_csp("default-src *");
        headers.insert("X-App-Version".to_string(), "9".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-App-Version").map(String::as_str), Some("9"));
    }

    #[test]
    fn given_blank_add_source_when_secure_then_ignores_token() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .add_source(CspDirective::ConnectSrc, CspSource::raw("   "));
        let shield = Shield::new().csp(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");
        let header = result.get("Content-Security-Policy").expect("csp header");

        assert_csp_directives(header, &["default-src 'self'"]);
        assert!(!header.contains("connect-src"));
    }
}

mod failure {
    use super::*;
    use bunner_shield_rs::{CspDirective, CspHashAlgorithm, CspSource};

    fn expect_validation_error(result: Result<Shield, ShieldError>) -> CspOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<CspOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_missing_directives_when_add_feature_then_returns_missing_directives_error() {
        let error = expect_validation_error(Shield::new().csp(CspOptions::new()));

        assert_eq!(error, CspOptionsError::MissingDirectives);
    }

    #[test]
    fn given_conflicting_none_when_add_feature_then_returns_conflicting_none_error() {
        let options = CspOptions::new().default_src([CspSource::None, CspSource::SelfKeyword]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::ConflictingNoneToken);
    }

    #[test]
    fn given_strict_dynamic_without_nonce_when_add_feature_then_returns_nonce_error() {
        let options =
            CspOptions::new().script_src(|script| script.sources([CspSource::StrictDynamic]));

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::StrictDynamicRequiresNonceOrHash);
    }

    #[test]
    fn given_whitespace_source_when_add_feature_then_returns_invalid_directive_value_error() {
        let options = CspOptions::new().default_src([CspSource::raw("   ")]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidDirectiveValue);
    }

    #[test]
    fn given_unterminated_token_when_add_feature_then_returns_invalid_directive_token_error() {
        let options = CspOptions::new().default_src([CspSource::raw("'unterminated")]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_short_nonce_when_add_feature_then_returns_invalid_nonce_error() {
        let options = CspOptions::new().script_src(|script| script.nonce("short"));

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidNonce);
    }

    #[test]
    fn given_invalid_hash_length_when_add_feature_then_returns_invalid_hash_error() {
        let options = CspOptions::new().script_src(|script| {
            script
                .sources([CspSource::SelfKeyword])
                .hash(CspHashAlgorithm::Sha256, "short")
        });

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidHash);
    }

    #[test]
    fn given_unsafe_hashes_without_hash_when_add_feature_then_returns_semantic_error() {
        let options = CspOptions::new().style_src(|style| style.sources([CspSource::UnsafeHashes]));

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(
            error,
            CspOptionsError::UnsafeHashesRequireHashes("style-src".to_string()),
        );
    }

    #[test]
    fn given_strict_dynamic_with_unsafe_inline_when_add_feature_then_returns_conflict_error() {
        let nonce = "a".repeat(22);
        let options = CspOptions::new().script_src(|script| {
            script
                .sources([CspSource::UnsafeInline])
                .nonce(nonce.clone())
                .strict_dynamic()
        });

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::StrictDynamicConflicts);
    }

    #[test]
    fn given_strict_dynamic_with_host_when_add_feature_then_returns_host_conflict_error() {
        let nonce = "a".repeat(22);
        let options = CspOptions::new().script_src(|script| {
            script
                .sources([CspSource::SelfKeyword])
                .nonce(nonce.clone())
                .strict_dynamic()
        });

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::StrictDynamicHostSourceConflict);
    }

    #[test]
    fn given_disallowed_scheme_when_add_feature_then_returns_disallowed_scheme_error() {
        let options = CspOptions::new()
            .script_src(|script| script.sources([CspSource::scheme("javascript")]));

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::DisallowedScheme(directive, scheme) => {
                assert_eq!(directive, "script-src");
                assert_eq!(scheme, "javascript");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_port_wildcard_when_add_feature_then_returns_port_wildcard_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .connect_src([CspSource::raw("https://api.example.com:*")]);

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::PortWildcardUnsupported(token) => {
                assert_eq!(token, "https://api.example.com:*");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_invalid_sandbox_token_when_add_feature_then_returns_error() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .add_source(CspDirective::Sandbox, CspSource::raw("allow-teleport"));

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::InvalidSandboxToken(token) => {
                assert_eq!(token, "allow-teleport".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_token_not_allowed_for_directive_when_add_feature_then_returns_error() {
        let options = CspOptions::new().img_src([CspSource::UnsafeInline]);

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'unsafe-inline'".to_string());
                assert_eq!(directive, "img-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_invalid_source_expression_when_add_feature_then_returns_error() {
        let options =
            CspOptions::new().img_src([CspSource::raw("https://user:secret@cdn.example.com")]);

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::InvalidSourceExpression(token) => {
                assert_eq!(token, "https://user:secret@cdn.example.com".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_path_source_with_whitespace_when_add_feature_then_returns_invalid_source_expression_error()
     {
        let options = CspOptions::new().img_src([CspSource::raw("/invalid\npath")]);

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidDirectiveToken);
    }

    #[test]
    fn given_style_src_attr_with_unsafe_eval_when_add_feature_then_returns_token_not_allowed_error()
    {
        let options = CspOptions::new().style_src(|style| style.attr([CspSource::UnsafeEval]));

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'unsafe-eval'".to_string());
                assert_eq!(directive, "style-src-attr".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_nonce_with_invalid_characters_when_add_feature_then_returns_invalid_nonce_error() {
        let options = CspOptions::new().script_src(|script| script.nonce("invalid!!nonce"));

        let error = expect_validation_error(Shield::new().csp(options));

        assert_eq!(error, CspOptionsError::InvalidNonce);
    }

    #[test]
    fn given_style_src_with_wasm_unsafe_eval_when_add_feature_then_returns_token_not_allowed_error()
    {
        let options =
            CspOptions::new().style_src(|style| style.sources([CspSource::WasmUnsafeEval]));

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'wasm-unsafe-eval'".to_string());
                assert_eq!(directive, "style-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_img_src_with_report_sample_when_add_feature_then_returns_token_not_allowed_error() {
        let options = CspOptions::new().img_src([CspSource::ReportSample]);

        let error = expect_validation_error(Shield::new().csp(options));

        match error {
            CspOptionsError::TokenNotAllowedForDirective(token, directive) => {
                assert_eq!(token, "'report-sample'".to_string());
                assert_eq!(directive, "img-src".to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
