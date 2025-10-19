use super::*;

mod parse {
    use super::*;

    #[test]
    fn given_known_token_when_from_str_then_returns_matching_variant() {
        let token = SandboxToken::parse("allow-popups");
        assert_eq!(token, Some(SandboxToken::AllowPopups));
    }

    #[test]
    fn given_unknown_token_when_from_str_then_returns_none() {
        let token = SandboxToken::parse("allow-everything");
        assert!(token.is_none());
    }
}

mod as_str {
    use super::*;

    #[test]
    fn given_all_sandbox_tokens_when_as_str_then_returns_expected_literals() {
        let expectations = [
            (SandboxToken::AllowDownloads, "allow-downloads"),
            (SandboxToken::AllowForms, "allow-forms"),
            (SandboxToken::AllowModals, "allow-modals"),
            (SandboxToken::AllowOrientationLock, "allow-orientation-lock"),
            (SandboxToken::AllowPointerLock, "allow-pointer-lock"),
            (SandboxToken::AllowPopups, "allow-popups"),
            (
                SandboxToken::AllowPopupsToEscapeSandbox,
                "allow-popups-to-escape-sandbox",
            ),
            (SandboxToken::AllowPresentation, "allow-presentation"),
            (SandboxToken::AllowSameOrigin, "allow-same-origin"),
            (SandboxToken::AllowScripts, "allow-scripts"),
            (
                SandboxToken::AllowStorageAccessByUserActivation,
                "allow-storage-access-by-user-activation",
            ),
            (SandboxToken::AllowTopNavigation, "allow-top-navigation"),
            (
                SandboxToken::AllowTopNavigationByUserActivation,
                "allow-top-navigation-by-user-activation",
            ),
            (
                SandboxToken::AllowTopNavigationToCustomProtocols,
                "allow-top-navigation-to-custom-protocols",
            ),
            (
                SandboxToken::AllowDownloadsWithoutUserActivation,
                "allow-downloads-without-user-activation",
            ),
        ];

        for (token, expected) in expectations {
            assert_eq!(token.as_str(), expected);
            assert_eq!(SandboxToken::parse(expected), Some(token));
        }
    }
}
