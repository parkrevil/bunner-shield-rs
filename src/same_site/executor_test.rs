use super::*;
use crate::SameSitePolicy;
use crate::executor::FeatureExecutor;
use crate::same_site::SameSiteOptionsError;
use crate::tests_common as common;

mod validate_options {
    use super::*;

    #[test]
    fn given_secure_same_site_options_when_validate_options_then_returns_ok() {
        let executor = SameSite::new(SameSiteOptions::new());

        let result = executor.validate_options();

        assert!(result.is_ok());
    }

    #[test]
    fn given_same_site_none_without_secure_when_validate_options_then_returns_error() {
        let executor = SameSite::new(
            SameSiteOptions::new()
                .secure(false)
                .same_site(SameSitePolicy::None),
        );

        let error = executor
            .validate_options()
            .expect_err("expected secure requirement error");

        assert_eq!(
            error.to_string(),
            SameSiteOptionsError::SameSiteNoneRequiresSecure.to_string()
        );
    }
}

mod options {
    use super::*;

    #[test]
    fn given_executor_when_options_then_returns_reference_to_options() {
        let options = SameSiteOptions::new().same_site(SameSitePolicy::Strict);
        let executor = SameSite::new(options);

        let result = executor.options();

        let expected = SameSiteOptions::new().same_site(SameSitePolicy::Strict);
        assert_eq!(result, &expected);
    }
}

mod execute {
    use super::*;

    #[test]
    fn given_headers_without_set_cookie_when_execute_then_leaves_headers_unchanged() {
        let executor = SameSite::new(SameSiteOptions::new());
        let mut headers = common::normalized_headers_from(&[("X-Test", "1")]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        assert_eq!(result.get("X-Test"), Some(&"1".to_string()));
        assert!(!result.contains_key("Set-Cookie"));
    }

    #[test]
    fn given_multi_cookie_headers_when_execute_then_overrides_same_site_attributes() {
        let executor = SameSite::new(SameSiteOptions::new());
        let mut headers = common::normalized_headers_from(&[(
            "Set-Cookie",
            "session=value; Path=/\ntracking=optin; SameSite=None",
        )]);

        executor
            .execute(&mut headers)
            .expect("execute should succeed");

        let result = headers.into_result();
        let updated = result
            .get("Set-Cookie")
            .expect("expected rewritten set-cookie header");
        let expected_first = "session=value; Path=/; Secure; HttpOnly; SameSite=Lax";
        let expected_second = "tracking=optin; Secure; HttpOnly; SameSite=Lax";
        assert_eq!(updated, &format!("{expected_first}\n{expected_second}"));
    }
}

mod apply_policy {
    use super::*;

    #[test]
    fn given_cookie_with_existing_flags_when_apply_policy_then_replaces_with_meta_settings() {
        let cookie = "session=value; Secure; HttpOnly; SameSite=None";
        let meta = CookieMeta::new(true, true, SameSitePolicy::Strict);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(updated, "session=value; Secure; HttpOnly; SameSite=Strict");
    }

    #[test]
    fn given_cookie_without_attributes_when_apply_policy_then_appends_required_flags() {
        let cookie = "pref=light";
        let meta = CookieMeta::new(false, true, SameSitePolicy::None);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(updated, "pref=light; HttpOnly; SameSite=None");
    }

    #[test]
    fn given_empty_cookie_when_apply_policy_then_preserves_empty_base() {
        let cookie = "";
        let meta = CookieMeta::new(true, true, SameSitePolicy::Lax);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(updated, "; Secure; HttpOnly; SameSite=Lax");
    }

    #[test]
    fn given_semicolon_only_cookie_when_apply_policy_then_normalizes_attributes() {
        let cookie = ";;;";
        let meta = CookieMeta::new(false, false, SameSitePolicy::Strict);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(updated, "; SameSite=Strict");
    }

    #[test]
    fn given_multiple_samesite_attributes_when_apply_policy_then_strips_all_occurrences() {
        let cookie = "id=123; SameSite=None; Path=/; SameSite=Lax; Domain=example.com";
        let meta = CookieMeta::new(true, false, SameSitePolicy::Strict);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(
            updated,
            "id=123; Path=/; Domain=example.com; Secure; SameSite=Strict"
        );
    }

    #[test]
    fn given_random_attribute_order_when_apply_policy_then_preserves_non_security_attrs() {
        let cookie = "token=xyz; Domain=app.io; Secure; Path=/admin; HttpOnly; Max-Age=600";
        let meta = CookieMeta::new(false, true, SameSitePolicy::Lax);

        let updated = apply_policy(cookie, &meta);

        assert_eq!(
            updated,
            "token=xyz; Domain=app.io; Path=/admin; Max-Age=600; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn given_very_long_cookie_when_apply_policy_then_processes_entire_string() {
        let long_value = "a".repeat(1024);
        let cookie = format!("bigcookie={long_value}; Secure");
        let meta = CookieMeta::new(true, true, SameSitePolicy::None);

        let updated = apply_policy(&cookie, &meta);

        assert!(updated.starts_with(&format!("bigcookie={long_value}")));
        assert!(updated.contains("Secure"));
        assert!(updated.contains("HttpOnly"));
        assert!(updated.contains("SameSite=None"));
    }
}
