use super::*;

mod nonce_utilities {
    use super::*;

    #[test]
    fn given_nonce_when_accessors_invoked_then_returns_expected_views() {
        let nonce = CspNonce {
            value: "abc123".to_string(),
        };
        assert_eq!(nonce.as_str(), "abc123");
        assert_eq!(nonce.header_value(), "'nonce-abc123'");
        assert_eq!(nonce.clone().into_inner(), "abc123".to_string());
    }
}

mod with_size {
    use super::*;

    #[test]
    fn given_zero_length_when_with_size_then_returns_invalid_length_error() {
        let error = CspNonceManager::with_size(0).expect_err("expected invalid length error");
        assert_eq!(error, CspNonceManagerError::InvalidLength);
    }
}

mod nonce_generation {
    use super::*;

    #[test]
    fn given_generate_nonce_when_called_then_returns_base64_value() {
        let value = generate_nonce();
        assert_eq!(value.len(), 44);
    }
}

mod issue_header_value {
    use super::*;

    #[test]
    fn given_manager_when_issue_header_value_then_returns_nonce_prefix() {
        let manager = CspNonceManager::with_size(8).expect("manager should be created");
        let header = manager.issue_header_value();
        assert!(header.starts_with("'nonce-"));
    }
}

mod nonce_manager_behaviour {
    use super::*;

    #[test]
    fn given_default_manager_when_issue_then_uses_default_length() {
        let manager = CspNonceManager::default();
        let nonce = manager.issue();
        assert_eq!(nonce.as_str().len(), 44);
    }
}
