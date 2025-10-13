use super::{XPermittedCrossDomainPoliciesOptions, XPermittedCrossDomainPoliciesPolicy};

mod header_value {
    use super::{XPermittedCrossDomainPoliciesOptions, XPermittedCrossDomainPoliciesPolicy};

    #[test]
    fn given_default_options_when_header_value_then_returns_none() {
        let options = XPermittedCrossDomainPoliciesOptions::new();

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_NONE
        );
    }

    #[test]
    fn given_master_only_policy_when_header_value_then_returns_master_only() {
        let options = XPermittedCrossDomainPoliciesOptions::new()
            .policy(XPermittedCrossDomainPoliciesPolicy::MasterOnly);

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_MASTER_ONLY
        );
    }

    #[test]
    fn given_by_content_type_policy_when_header_value_then_returns_by_content_type() {
        let options = XPermittedCrossDomainPoliciesOptions::new()
            .policy(XPermittedCrossDomainPoliciesPolicy::ByContentType);

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_BY_CONTENT_TYPE
        );
    }

    #[test]
    fn given_all_policy_when_header_value_then_returns_all() {
        let options = XPermittedCrossDomainPoliciesOptions::new()
            .policy(XPermittedCrossDomainPoliciesPolicy::All);

        assert_eq!(
            options.header_value(),
            crate::constants::header_values::X_PERMITTED_CROSS_DOMAIN_POLICIES_ALL
        );
    }
}
