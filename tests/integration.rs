use bunner_shield_rs::{
    ClearSiteDataOptions, CoepOptions, CoepPolicy, CoopOptions, CoopPolicy, CorpOptions,
    CorpPolicy, CspOptions, CspOptionsError, CspSource, CsrfOptions, CsrfOptionsError, HstsOptions,
    HstsOptionsError, OriginAgentClusterOptions, PermissionsPolicyOptions,
    PermissionsPolicyOptionsError, ReferrerPolicyOptions, ReferrerPolicyValue, SameSiteOptions,
    SameSitePolicy, Shield, ShieldError, XFrameOptionsOptions, XFrameOptionsPolicy,
    XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy, header_keys, header_values,
};
use std::collections::HashMap;

fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn base_secret() -> [u8; 32] {
    [0x11; 32]
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
            header_keys::CROSS_ORIGIN_OPENER_POLICY.to_string(),
            "unsafe-none".to_string(),
        );
        headers.insert(
            header_keys::STRICT_TRANSPORT_SECURITY.to_string(),
            "max-age=0".to_string(),
        );

        let secured = shield.secure(headers).expect("secure");

        let csp = secured
            .get(header_keys::CONTENT_SECURITY_POLICY)
            .expect("csp header");
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));

        assert_eq!(
            secured
                .get(header_keys::STRICT_TRANSPORT_SECURITY)
                .map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            secured
                .get(header_keys::X_CONTENT_TYPE_OPTIONS)
                .map(String::as_str),
            Some(header_values::NOSNIFF)
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_CREDENTIALLESS)
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN_ALLOW_POPUPS)
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_CROSS_ORIGIN)
        );
        assert_eq!(
            secured
                .get(header_keys::X_FRAME_OPTIONS)
                .map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            secured
                .get(header_keys::REFERRER_POLICY)
                .map(String::as_str),
            Some(header_values::REFERRER_POLICY_STRICT_ORIGIN)
        );
        assert_eq!(
            secured
                .get(header_keys::ORIGIN_AGENT_CLUSTER)
                .map(String::as_str),
            Some(header_values::ORIGIN_AGENT_CLUSTER_DISABLE)
        );
        assert_eq!(
            secured
                .get(header_keys::PERMISSIONS_POLICY)
                .map(String::as_str),
            Some("geolocation=()")
        );
        assert_eq!(
            secured
                .get(header_keys::X_DNS_PREFETCH_CONTROL)
                .map(String::as_str),
            Some(header_values::X_DNS_PREFETCH_CONTROL_ON)
        );
        let clear_site_data_value = [
            header_values::CLEAR_SITE_DATA_CACHE,
            header_values::CLEAR_SITE_DATA_COOKIES,
            header_values::CLEAR_SITE_DATA_STORAGE,
            header_values::CLEAR_SITE_DATA_EXECUTION_CONTEXTS,
        ]
        .join(", ");

        assert_eq!(
            secured
                .get(header_keys::CLEAR_SITE_DATA)
                .map(String::as_str),
            Some(clear_site_data_value.as_str())
        );
        assert!(!secured.contains_key(header_keys::X_POWERED_BY));
        assert_eq!(
            secured.get("Content-Type").map(String::as_str),
            Some("application/json")
        );

        let csrf_token = secured
            .get(header_keys::CSRF_TOKEN)
            .expect("csrf token present");
        assert_eq!(csrf_token.len(), 64);
        assert!(csrf_token.chars().all(|c| c.is_ascii_hexdigit()));

        let cookie = secured
            .get(header_keys::SET_COOKIE)
            .expect("csrf cookie present");
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
            header_keys::STRICT_TRANSPORT_SECURITY.to_string(),
            "max-age=0".to_string(),
        );
        headers.insert(
            header_keys::CROSS_ORIGIN_EMBEDDER_POLICY.to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            header_keys::CROSS_ORIGIN_OPENER_POLICY.to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            header_keys::CROSS_ORIGIN_RESOURCE_POLICY.to_string(),
            "unsafe".to_string(),
        );
        headers.insert(
            header_keys::REFERRER_POLICY.to_string(),
            "unsafe-url".to_string(),
        );

        let secured = shield.secure(headers).expect("secure");

        assert_eq!(
            secured
                .get(header_keys::STRICT_TRANSPORT_SECURITY)
                .map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_EMBEDDER_POLICY)
                .map(String::as_str),
            Some(header_values::COEP_REQUIRE_CORP)
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_OPENER_POLICY)
                .map(String::as_str),
            Some(header_values::COOP_SAME_ORIGIN)
        );
        assert_eq!(
            secured
                .get(header_keys::CROSS_ORIGIN_RESOURCE_POLICY)
                .map(String::as_str),
            Some(header_values::CORP_SAME_ORIGIN)
        );
        assert_eq!(
            secured
                .get(header_keys::REFERRER_POLICY)
                .map(String::as_str),
            Some(header_values::REFERRER_POLICY_STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
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

        let cookie = secured
            .get(header_keys::SET_COOKIE)
            .expect("cookie present");
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
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
