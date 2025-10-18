use super::*;
use crate::SameSitePolicy;
use crate::tests_common as common;

mod options_access {
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

mod apply_policy_fn {
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
}
