use bunner_shield_rs::{
    ClearSiteDataOptions, CoepOptions, CoepPolicy, CoopOptions, CoopPolicy, CorpOptions,
    CorpPolicy, CspNonceManager, CspOptions, CspOptionsError, CspSource, CsrfOptions,
    CsrfOptionsError, HstsOptions, HstsOptionsError, OriginAgentClusterOptions,
    PermissionsPolicyOptions, PermissionsPolicyOptionsError, ReferrerPolicyOptions,
    ReferrerPolicyValue, SameSiteOptions, SameSiteOptionsError, SameSitePolicy, Shield,
    ShieldError, XFrameOptionsOptions, XFrameOptionsPolicy, XdnsPrefetchControlOptions,
    XdnsPrefetchControlPolicy,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn base_secret() -> [u8; 32] {
    [0x11; 32]
}

fn assert_clear_site_data(actual: &str, expected: &[&str]) {
    let mut actual_tokens: Vec<_> = actual
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    let mut expected_tokens: Vec<_> = expected.to_vec();

    actual_tokens.sort_unstable();
    expected_tokens.sort_unstable();

    assert_eq!(actual_tokens, expected_tokens);
}

fn expect_validation_error<T>(result: Result<Shield, ShieldError>) -> T
where
    T: std::error::Error + Send + Sync + 'static,
{
    let err = match result {
        Err(ShieldError::ExecutorValidationFailed(err)) => err,
        Err(ShieldError::ExecutionFailed(err)) => {
            panic!("expected validation failure, got execution error: {err}")
        }
        Ok(_) => panic!("expected validation failure but feature was accepted"),
    };

    err.downcast::<T>()
        .map(|boxed| *boxed)
        .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
}

mod success {
    use super::*;

    #[test]
    fn given_full_security_suite_when_secure_then_sets_expected_headers() {
        let shield = Shield::new()
            .csp(
                CspOptions::new()
                    .default_src([CspSource::SelfKeyword])
                    .script_src([CspSource::SelfKeyword])
                    .base_uri([CspSource::None])
                    .frame_ancestors([CspSource::None]),
            )
            .expect("csp")
            .x_powered_by()
            .expect("x-powered-by")
            .hsts(HstsOptions::new().include_subdomains())
            .expect("hsts")
            .x_content_type_options()
            .expect("xcto")
            .csrf(CsrfOptions::new(base_secret()))
            .expect("csrf")
            .same_site(SameSiteOptions::new().same_site(SameSitePolicy::Strict))
            .expect("same-site")
            .coep(CoepOptions::new().policy(CoepPolicy::Credentialless))
            .expect("coep")
            .coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))
            .expect("coop")
            .corp(CorpOptions::new().policy(CorpPolicy::CrossOrigin))
            .expect("corp")
            .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
            .expect("xfo")
            .referrer_policy(ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::StrictOrigin))
            .expect("referrer-policy")
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("oac")
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("permissions-policy")
            .x_dns_prefetch_control(
                XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
            )
            .expect("x-dns-prefetch")
            .clear_site_data(
                ClearSiteDataOptions::new()
                    .cache()
                    .cookies()
                    .storage()
                    .execution_contexts(),
            )
            .expect("clear-site-data");

        let mut headers = empty_headers();
        headers.insert("X-Powered-By".to_string(), "Express".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert(
            "Cross-Origin-Opener-Policy".to_string(),
            "unsafe-none".to_string(),
        );
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=0".to_string(),
        );

        let secured = shield.secure(headers).expect("secure");

        let csp = secured.get("Content-Security-Policy").expect("csp header");
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));

        assert_eq!(
            secured.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            secured.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("credentialless")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Opener-Policy")
                .map(String::as_str),
            Some("same-origin-allow-popups")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Resource-Policy")
                .map(String::as_str),
            Some("cross-origin")
        );
        assert_eq!(
            secured.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            secured.get("Referrer-Policy").map(String::as_str),
            Some("strict-origin")
        );
        assert_eq!(
            secured.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?0")
        );
        assert_eq!(
            secured.get("Permissions-Policy").map(String::as_str),
            Some("geolocation=()")
        );
        assert_eq!(
            secured.get("X-DNS-Prefetch-Control").map(String::as_str),
            Some("on")
        );
        let clear_site_data_value = [
            "\"cache\"",
            "\"cookies\"",
            "\"storage\"",
            "\"executionContexts\"",
        ];

        let clear_site_data_header = secured
            .get("Clear-Site-Data")
            .map(String::to_string)
            .expect("clear-site-data header");
        assert_clear_site_data(&clear_site_data_header, &clear_site_data_value);
        assert!(!secured.contains_key("X-Powered-By"));
        assert_eq!(
            secured.get("Content-Type").map(String::as_str),
            Some("application/json")
        );

        let csrf_token = secured.get("X-CSRF-Token").expect("csrf token present");
        assert_eq!(csrf_token.len(), 64);
        assert!(csrf_token.chars().all(|c| c.is_ascii_hexdigit()));

        let cookie = secured.get("Set-Cookie").expect("csrf cookie present");
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn given_conflicting_header_values_when_secure_then_pipeline_overwrites_all() {
        let shield = Shield::new()
            .hsts(HstsOptions::new().include_subdomains())
            .expect("hsts")
            .coep(CoepOptions::new())
            .expect("coep")
            .coop(CoopOptions::new())
            .expect("coop")
            .corp(CorpOptions::new())
            .expect("corp")
            .referrer_policy(ReferrerPolicyOptions::new())
            .expect("referrer");

        let mut headers = empty_headers();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=0".to_string(),
        );
        headers.insert(
            "Cross-Origin-Embedder-Policy".to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            "Cross-Origin-Opener-Policy".to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            "Cross-Origin-Resource-Policy".to_string(),
            "unsafe".to_string(),
        );
        headers.insert("Referrer-Policy".to_string(), "unsafe-url".to_string());

        let secured = shield.secure(headers).expect("secure");

        assert_eq!(
            secured.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("require-corp")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Opener-Policy")
                .map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(
            secured
                .get("Cross-Origin-Resource-Policy")
                .map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(
            secured.get("Referrer-Policy").map(String::as_str),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[test]
    fn given_csrf_and_same_site_when_secure_then_cookie_policy_is_upgraded() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(base_secret()))
            .expect("csrf")
            .same_site(SameSiteOptions::new().same_site(SameSitePolicy::Strict))
            .expect("same-site");

        let secured = shield.secure(empty_headers()).expect("secure");

        let cookie = secured.get("Set-Cookie").expect("cookie present");
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn given_existing_multiple_cookies_when_secure_then_upgrades_each_entry() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(base_secret()))
            .expect("csrf")
            .same_site(SameSiteOptions::new().same_site(SameSitePolicy::Strict))
            .expect("same-site");

        let mut headers = empty_headers();
        headers.insert(
            "Set-Cookie".to_string(),
            "session=abc; Path=/\ntracking=1".to_string(),
        );

        let secured = shield.secure(headers).expect("secure");

        let cookies = secured.get("Set-Cookie").expect("cookies present");
        let mut lines: Vec<&str> = cookies.split('\n').collect();
        lines.sort();

        assert_eq!(lines.len(), 3);
        assert!(lines.iter().any(|line| line.starts_with("session=abc")));
        assert!(lines.iter().any(|line| line.starts_with("tracking=1")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("__Host-csrf-token=") && line.contains("SameSite=Strict"))
        );
        for line in &lines {
            assert!(line.contains("SameSite=Strict"));
            assert!(line.contains("Secure"));
            assert!(line.contains("HttpOnly"));
        }
    }

    #[test]
    fn given_lowercase_headers_when_secure_then_emits_canonical_casing() {
        let shield = Shield::new()
            .hsts(HstsOptions::new().include_subdomains())
            .expect("hsts")
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("permissions-policy")
            .coep(CoepOptions::new())
            .expect("coep")
            .coop(CoopOptions::new())
            .expect("coop");

        let mut headers = empty_headers();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=0".to_string(),
        );
        headers.insert("permissions-policy".to_string(), "camera=()".to_string());
        headers.insert(
            "cross-origin-embedder-policy".to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            "cross-origin-opener-policy".to_string(),
            "unsafe".to_string(),
        );

        let secured = shield.secure(headers).expect("secure");

        assert!(secured.contains_key("Strict-Transport-Security"));
        assert!(secured.contains_key("Permissions-Policy"));
        assert!(secured.contains_key("Cross-Origin-Embedder-Policy"));
        assert!(secured.contains_key("Cross-Origin-Opener-Policy"));

        assert!(!secured.contains_key("strict-transport-security"));
        assert!(!secured.contains_key("permissions-policy"));
        assert!(!secured.contains_key("cross-origin-embedder-policy"));
        assert!(!secured.contains_key("cross-origin-opener-policy"));
    }

    #[test]
    fn given_strict_dynamic_with_nonce_when_secure_then_emits_expected_tokens() {
        let nonce_manager = CspNonceManager::new();
        let nonce = nonce_manager.issue();
        let nonce_value = nonce.clone().into_inner();

        let shield = Shield::new()
            .csp(
                CspOptions::new()
                    .default_src([CspSource::SelfKeyword])
                    .enable_strict_dynamic()
                    .script_src_with_nonce(nonce),
            )
            .expect("csp");

        let secured = shield.secure(empty_headers()).expect("secure");

        let header = secured
            .get("Content-Security-Policy")
            .map(String::to_string)
            .expect("csp header");

        assert!(header.contains("'strict-dynamic'"));
        assert!(header.contains(&format!("'nonce-{nonce_value}'")));
    }
}

mod failure {
    use super::*;

    #[test]
    fn given_invalid_permissions_policy_when_add_feature_then_returns_empty_policy_error() {
        let error: PermissionsPolicyOptionsError = expect_validation_error(
            Shield::new()
                .x_content_type_options()
                .expect("xcto")
                .permissions_policy(PermissionsPolicyOptions::new("   ")),
        );

        assert!(matches!(error, PermissionsPolicyOptionsError::EmptyPolicy));
    }

    #[test]
    fn given_same_site_none_without_secure_when_add_feature_then_returns_validation_error() {
        let options = SameSiteOptions::new()
            .secure(false)
            .same_site(SameSitePolicy::None);

        let error: SameSiteOptionsError = expect_validation_error(
            Shield::new()
                .csrf(CsrfOptions::new(base_secret()))
                .expect("csrf")
                .same_site(options),
        );

        assert!(matches!(
            error,
            SameSiteOptionsError::SameSiteNoneRequiresSecure
        ));
    }

    #[test]
    fn given_invalid_csrf_configuration_when_add_feature_then_returns_token_length_error() {
        let error: CsrfOptionsError = expect_validation_error(
            Shield::new().csrf(CsrfOptions::new(base_secret()).token_length(100)),
        );

        match error {
            CsrfOptionsError::InvalidTokenLength {
                requested,
                minimum,
                maximum,
            } => {
                assert_eq!(requested, 100);
                assert_eq!(minimum, 32);
                assert_eq!(maximum, 64);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn given_invalid_hsts_configuration_when_add_feature_then_returns_validation_error() {
        let error: HstsOptionsError =
            expect_validation_error(Shield::new().hsts(HstsOptions::new().preload()));

        assert!(matches!(
            error,
            HstsOptionsError::PreloadRequiresIncludeSubdomains
        ));
    }

    #[test]
    fn given_csp_missing_directives_when_add_feature_then_returns_missing_directives_error() {
        let error: CspOptionsError = expect_validation_error(Shield::new().csp(CspOptions::new()));

        assert!(matches!(error, CspOptionsError::MissingDirectives));
    }
}
