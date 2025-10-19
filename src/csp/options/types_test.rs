use super::*;

mod prefix {
    use super::*;

    #[test]
    fn given_sha256_algorithm_when_prefix_then_returns_sha256_marker() {
        assert_eq!(CspHashAlgorithm::Sha256.prefix(), "sha256-");
    }

    #[test]
    fn given_sha512_algorithm_when_prefix_then_returns_sha512_marker() {
        assert_eq!(CspHashAlgorithm::Sha512.prefix(), "sha512-");
    }
}

mod as_str {
    use super::*;

    #[test]
    fn given_default_src_directive_when_as_str_then_returns_default_src_name() {
        assert_eq!(CspDirective::DefaultSrc.as_str(), "default-src");
    }

    #[test]
    fn given_trusted_types_directive_when_as_str_then_returns_trusted_types_name() {
        assert_eq!(CspDirective::TrustedTypes.as_str(), "trusted-types");
    }
}
