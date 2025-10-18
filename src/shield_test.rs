use super::*;
use crate::tests_common as common;

mod new {
    use super::*;

    #[test]
    fn given_new_shield_when_secure_then_returns_original_headers() {
        let shield = Shield::new();
        let headers = common::headers_with(&[("X-App", "1")]);

        let result = shield.secure(headers.clone()).expect("secure");

        assert_eq!(result, headers);
    }
}

mod x_powered_by_feature {
    use super::*;

    #[test]
    fn given_x_powered_by_header_when_feature_applied_then_removes_header() {
        let shield = Shield::new().x_powered_by().expect("feature");
        let headers = common::headers_with(&[("X-Powered-By", "Rocket"), ("X-App", "1")]);

        let result = shield.secure(headers).expect("secure");

        assert!(!result.contains_key("X-Powered-By"));
        assert_eq!(result.get("X-App").map(String::as_str), Some("1"));
    }
}

mod multi_feature_pipeline {
    use super::*;

    #[test]
    fn given_multiple_features_when_secure_then_applies_in_configured_order() {
        let shield = Shield::new()
            .x_content_type_options()
            .expect("feature")
            .x_powered_by()
            .expect("feature");
        let headers = common::headers_with(&[("X-Powered-By", "Rocket")]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
        assert!(!result.contains_key("X-Powered-By"));
    }
}

mod validation_failure {
    use super::*;
    use crate::csp::CspOptions;

    #[test]
    fn given_invalid_options_when_feature_added_then_returns_executor_validation_error() {
        let error = Shield::new().csp(CspOptions::new());

        match error {
            Err(ShieldError::ExecutorValidationFailed(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("expected validation failure"),
        }
    }
}

mod csp {
    use super::*;
    use crate::csp::{CspOptions, CspSource};

    #[test]
    fn given_valid_csp_options_when_feature_applied_then_sets_csp_header() {
        let options = CspOptions::new()
            .default_src([CspSource::SelfKeyword])
            .base_uri([CspSource::None])
            .frame_ancestors([CspSource::None]);
        let shield = Shield::new().csp(options).expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Content-Security-Policy").map(String::as_str),
            Some("default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        );
    }
}

mod coop {
    use super::*;
    use crate::coop::{CoopOptions, CoopPolicy};

    #[test]
    fn given_allow_popups_policy_when_feature_applied_then_sets_coop_header() {
        let shield = Shield::new()
            .coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Cross-Origin-Opener-Policy").map(String::as_str),
            Some("same-origin-allow-popups")
        );
    }
}

mod corp {
    use super::*;
    use crate::corp::{CorpOptions, CorpPolicy};

    #[test]
    fn given_cross_origin_policy_when_feature_applied_then_sets_corp_header() {
        let shield = Shield::new()
            .corp(CorpOptions::new().policy(CorpPolicy::CrossOrigin))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Resource-Policy")
                .map(String::as_str),
            Some("cross-origin")
        );
    }
}

mod hsts {
    use super::*;
    use crate::hsts::{HstsOptions, HstsOptionsError};

    #[test]
    fn given_default_hsts_options_when_feature_applied_then_sets_hsts_header() {
        let shield = Shield::new().hsts(HstsOptions::new()).expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000")
        );
    }

    #[test]
    fn given_invalid_hsts_options_when_feature_added_then_returns_validation_error() {
        let result = Shield::new().hsts(HstsOptions::new().max_age(0));

        match result {
            Err(ShieldError::ExecutorValidationFailed(error)) => {
                assert_eq!(
                    error.to_string(),
                    HstsOptionsError::InvalidMaxAge.to_string()
                );
            }
            _ => panic!("expected validation failure"),
        }
    }
}

mod csrf {
    use super::*;
    use crate::csrf::{CsrfOptions, CsrfOptionsError};

    fn secret_key() -> [u8; 32] {
        [0x5Au8; 32]
    }

    #[test]
    fn given_valid_csrf_options_when_feature_applied_then_sets_token_and_cookie() {
        let shield = Shield::new()
            .csrf(CsrfOptions::new(secret_key()))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");
        let token = result.get("X-CSRF-Token").expect("csrf token header");
        let cookie = result.get("Set-Cookie").expect("csrf cookie header");

        assert_eq!(token.len(), 64);
        assert!(cookie.starts_with("__Host-csrf-token="));
        assert!(cookie.contains("; Path=/; Secure; HttpOnly; SameSite=Lax"));
    }

    #[test]
    fn given_cookie_without_host_prefix_when_feature_added_then_returns_validation_error() {
        let result = Shield::new().csrf(CsrfOptions::new(secret_key()).cookie_name("csrf"));

        match result {
            Err(ShieldError::ExecutorValidationFailed(error)) => {
                assert_eq!(
                    error.to_string(),
                    CsrfOptionsError::InvalidCookiePrefix.to_string()
                );
            }
            _ => panic!("expected validation failure"),
        }
    }
}

mod permissions_policy {
    use super::*;
    use crate::permissions_policy::{PermissionsPolicyOptions, PermissionsPolicyOptionsError};

    #[test]
    fn given_permissions_policy_when_feature_applied_then_sets_header_value() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("geolocation=()")
        );
    }

    #[test]
    fn given_blank_permissions_policy_when_feature_added_then_returns_validation_error() {
        let result = Shield::new().permissions_policy(PermissionsPolicyOptions::new("  "));

        match result {
            Err(ShieldError::ExecutorValidationFailed(error)) => {
                assert_eq!(
                    error.to_string(),
                    PermissionsPolicyOptionsError::EmptyPolicy.to_string()
                );
            }
            _ => panic!("expected validation failure"),
        }
    }
}

mod x_dns_prefetch_control {
    use super::*;
    use crate::x_dns_prefetch_control::{XdnsPrefetchControlOptions, XdnsPrefetchControlPolicy};

    #[test]
    fn given_on_policy_when_feature_applied_then_sets_dns_prefetch_header() {
        let shield = Shield::new()
            .x_dns_prefetch_control(
                XdnsPrefetchControlOptions::new().policy(XdnsPrefetchControlPolicy::On),
            )
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("X-DNS-Prefetch-Control").map(String::as_str),
            Some("on")
        );
    }
}

mod clear_site_data {
    use super::*;
    use crate::clear_site_data::{ClearSiteDataOptions, ClearSiteDataOptionsError};

    #[test]
    fn given_all_sections_when_feature_applied_then_sets_clear_site_data_header() {
        let options = ClearSiteDataOptions::new()
            .cache()
            .cookies()
            .storage()
            .execution_contexts();
        let shield = Shield::new().clear_site_data(options).expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Clear-Site-Data").map(String::as_str),
            Some("\"cache\", \"cookies\", \"storage\", \"executionContexts\"")
        );
    }

    #[test]
    fn given_no_sections_when_feature_added_then_returns_validation_error() {
        let result = Shield::new().clear_site_data(ClearSiteDataOptions::new());

        match result {
            Err(ShieldError::ExecutorValidationFailed(error)) => {
                assert_eq!(
                    error.to_string(),
                    ClearSiteDataOptionsError::NoSectionsSelected.to_string()
                );
            }
            _ => panic!("expected validation failure"),
        }
    }
}

mod x_frame_options {
    use super::*;
    use crate::x_frame_options::{XFrameOptionsOptions, XFrameOptionsPolicy};

    #[test]
    fn given_same_origin_policy_when_feature_applied_then_sets_x_frame_options_header() {
        let shield = Shield::new()
            .x_frame_options(XFrameOptionsOptions::new().policy(XFrameOptionsPolicy::SameOrigin))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
    }
}

mod referrer_policy {
    use super::*;
    use crate::referrer_policy::{ReferrerPolicyOptions, ReferrerPolicyValue};

    #[test]
    fn given_referrer_policy_when_feature_applied_then_sets_header_value() {
        let options = ReferrerPolicyOptions::new().policy(ReferrerPolicyValue::NoReferrer);
        let shield = Shield::new().referrer_policy(options).expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Referrer-Policy").map(String::as_str),
            Some("no-referrer")
        );
    }
}

mod origin_agent_cluster {
    use super::*;
    use crate::origin_agent_cluster::OriginAgentClusterOptions;

    #[test]
    fn given_disabled_cluster_when_feature_applied_then_sets_origin_agent_cluster_header() {
        let shield = Shield::new()
            .origin_agent_cluster(OriginAgentClusterOptions::new().disable())
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Origin-Agent-Cluster").map(String::as_str),
            Some("?0")
        );
    }
}

mod same_site {
    use super::*;
    use crate::same_site::{SameSiteOptions, SameSiteOptionsError, SameSitePolicy};

    #[test]
    fn given_same_site_strict_when_feature_applied_then_overrides_cookies() {
        let options = SameSiteOptions::new().same_site(SameSitePolicy::Strict);
        let shield = Shield::new().same_site(options).expect("feature");
        let headers = common::headers_with(&[("Set-Cookie", "session=1; Secure")]);

        let result = shield.secure(headers).expect("secure");
        let updated = result.get("Set-Cookie").expect("set-cookie header");

        assert!(updated.contains("SameSite=Strict"));
        assert!(updated.contains("Secure"));
        assert!(updated.contains("HttpOnly"));
    }

    #[test]
    fn given_same_site_none_without_secure_when_feature_added_then_returns_validation_error() {
        let options = SameSiteOptions::new()
            .secure(false)
            .same_site(SameSitePolicy::None);

        let result = Shield::new().same_site(options);

        match result {
            Err(ShieldError::ExecutorValidationFailed(error)) => {
                assert_eq!(
                    error.to_string(),
                    SameSiteOptionsError::SameSiteNoneRequiresSecure.to_string()
                );
            }
            _ => panic!("expected validation failure"),
        }
    }
}

mod coep {
    use super::*;
    use crate::coep::{CoepOptions, CoepPolicy};

    #[test]
    fn given_credentialless_policy_when_feature_applied_then_sets_coep_header() {
        let shield = Shield::new()
            .coep(CoepOptions::new().policy(CoepPolicy::Credentialless))
            .expect("feature");
        let headers = common::headers_with(&[]);

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result
                .get("Cross-Origin-Embedder-Policy")
                .map(String::as_str),
            Some("credentialless")
        );
    }
}

mod execution_failure {
    use super::*;
    use crate::executor::{Executor, FeatureExecutor, NoopOptions};
    use crate::tests_common as common;
    use std::fmt;

    #[derive(Debug)]
    struct IntentionalFailure;

    impl fmt::Display for IntentionalFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("intentional failure")
        }
    }

    impl std::error::Error for IntentionalFailure {}

    struct FailingExecutor {
        options: NoopOptions,
    }

    impl FailingExecutor {
        fn new() -> Self {
            Self {
                options: NoopOptions,
            }
        }
    }

    impl FeatureExecutor for FailingExecutor {
        type Options = NoopOptions;

        fn options(&self) -> &Self::Options {
            &self.options
        }

        fn execute(&self, _headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
            Err(Box::new(IntentionalFailure))
        }
    }

    #[test]
    fn given_executor_failure_when_secure_then_returns_execution_error() {
        let mut shield = Shield::new();
        let executor: Executor = Box::new(FailingExecutor::new());

        shield
            .add_feature(0, executor)
            .expect("failed to register failing executor");

        let error = shield
            .secure(common::headers_with(&[]))
            .expect_err("expected execution failure");

        match error {
            ShieldError::ExecutionFailed(inner) => {
                assert_eq!(inner.to_string(), "intentional failure");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
