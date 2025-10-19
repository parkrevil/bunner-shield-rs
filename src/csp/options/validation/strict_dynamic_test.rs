use super::*;

mod strict_dynamic_has_host_sources {
    use super::*;

    #[test]
    fn given_strict_dynamic_and_self_when_checking_host_sources_then_detects_conflict() {
        let script_src = "'strict-dynamic' 'self'";
        assert!(strict_dynamic_has_host_sources(Some(script_src), None));
    }
}

mod validate_strict_dynamic_host_sources {
    use super::*;

    #[test]
    fn given_strict_dynamic_with_nonce_only_when_validating_host_sources_then_allows() {
        validate_strict_dynamic_host_sources(Some("'strict-dynamic' 'nonce-token'"), None)
            .expect("nonce backed strict-dynamic should be accepted");
    }
}
