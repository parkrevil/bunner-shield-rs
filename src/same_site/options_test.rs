use super::*;
use crate::constants::header_values::{SAMESITE_LAX, SAMESITE_NONE, SAMESITE_STRICT};

mod policy_as_str {
    use super::*;

    #[test]
    fn given_lax_policy_when_as_str_then_returns_lax_constant() {
        let policy = SameSitePolicy::Lax;

        assert_eq!(policy.as_str(), SAMESITE_LAX);
    }

    #[test]
    fn given_strict_policy_when_as_str_then_returns_strict_constant() {
        let policy = SameSitePolicy::Strict;

        assert_eq!(policy.as_str(), SAMESITE_STRICT);
    }

    #[test]
    fn given_none_policy_when_as_str_then_returns_none_constant() {
        let policy = SameSitePolicy::None;

        assert_eq!(policy.as_str(), SAMESITE_NONE);
    }
}

mod defaults {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_uses_secure_http_only_lax_defaults() {
        let options = SameSiteOptions::new();

        assert!(options.meta.secure);
        assert!(options.meta.http_only);
        assert_eq!(options.meta.same_site, SameSitePolicy::Lax);
    }
}

mod builder {
    use super::*;

    #[test]
    fn given_false_when_secure_then_updates_secure_flag() {
        let options = SameSiteOptions::new().secure(false);

        assert!(!options.meta.secure);
    }

    #[test]
    fn given_false_when_http_only_then_updates_http_only_flag() {
        let options = SameSiteOptions::new().http_only(false);

        assert!(!options.meta.http_only);
    }

    #[test]
    fn given_policy_when_same_site_then_updates_policy_field() {
        let options = SameSiteOptions::new().same_site(SameSitePolicy::Strict);

        assert_eq!(options.meta.same_site, SameSitePolicy::Strict);
    }
}

mod validation {
    use super::*;

    #[test]
    fn given_same_site_none_without_secure_when_validate_then_returns_error() {
        let options = SameSiteOptions::new()
            .secure(false)
            .same_site(SameSitePolicy::None);

        let error = options
            .validate()
            .expect_err("expected same site secure error");

        assert_eq!(error, SameSiteOptionsError::SameSiteNoneRequiresSecure);
    }

    #[test]
    fn given_same_site_none_with_secure_when_validate_then_returns_ok() {
        let options = SameSiteOptions::new().same_site(SameSitePolicy::None);

        let result = options.validate();

        assert!(result.is_ok());
    }
}
