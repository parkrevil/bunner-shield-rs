use super::*;
use crate::constants::header_values::{
    COOP_SAME_ORIGIN, COOP_SAME_ORIGIN_ALLOW_POPUPS, COOP_UNSAFE_NONE,
};

mod as_str {
    use super::*;

    #[test]
    fn given_same_origin_policy_when_as_str_then_returns_same_origin_constant() {
        let policy = CoopPolicy::SameOrigin;

        let value = policy.as_str();

        assert_eq!(value, COOP_SAME_ORIGIN);
    }

    #[test]
    fn given_same_origin_allow_popups_policy_when_as_str_then_returns_allow_popups_constant() {
        let policy = CoopPolicy::SameOriginAllowPopups;

        let value = policy.as_str();

        assert_eq!(value, COOP_SAME_ORIGIN_ALLOW_POPUPS);
    }

    #[test]
    fn given_unsafe_none_policy_when_as_str_then_returns_unsafe_none_constant() {
        let policy = CoopPolicy::UnsafeNone;

        let value = policy.as_str();

        assert_eq!(value, COOP_UNSAFE_NONE);
    }
}

mod from_str {
    use super::*;

    #[test]
    fn given_same_origin_text_when_parse_then_returns_same_origin_policy() {
        let policy: CoopPolicy = "same-origin".parse().expect("parse should succeed");

        assert_eq!(policy, CoopPolicy::SameOrigin);
    }

    #[test]
    fn given_allow_popups_text_when_parse_then_returns_allow_popups_policy() {
        let policy: CoopPolicy = "same-origin-allow-popups"
            .parse()
            .expect("parse should succeed");

        assert_eq!(policy, CoopPolicy::SameOriginAllowPopups);
    }

    #[test]
    fn given_trimmed_mixed_case_text_when_parse_then_returns_policy_case_insensitively() {
        let policy: CoopPolicy = "  Unsafe-None  ".parse().expect("parse should succeed");

        assert_eq!(policy, CoopPolicy::UnsafeNone);
    }

    #[test]
    fn given_unknown_text_when_parse_then_returns_invalid_policy_error() {
        let error = "invalid".parse::<CoopPolicy>().unwrap_err();

        assert_eq!(
            error,
            CoopOptionsError::InvalidPolicy("invalid".to_string())
        );
    }

    #[test]
    fn given_tab_and_newline_padding_when_parse_then_trims_and_parses_policy() {
        let policy: CoopPolicy = "\t\nsame-origin\r\n".parse().expect("parse should succeed");

        assert_eq!(policy, CoopPolicy::SameOrigin);
    }

    #[test]
    fn given_tabs_and_spaces_with_allow_popups_when_parse_then_parses_case_insensitively() {
        let policy: CoopPolicy = " \t SaMe-OrIgIn-AlLoW-PoPuPs \n"
            .parse()
            .expect("parse should succeed");

        assert_eq!(policy, CoopPolicy::SameOriginAllowPopups);
    }
}

mod new {
    use super::*;

    #[test]
    fn given_new_options_when_created_then_defaults_to_same_origin_policy() {
        let options = CoopOptions::new();

        assert_eq!(options.policy, CoopPolicy::SameOrigin);
    }
}

mod policy {
    use super::*;

    #[test]
    fn given_explicit_policy_when_policy_then_sets_policy_on_builder() {
        let options = CoopOptions::new().policy(CoopPolicy::UnsafeNone);

        assert_eq!(options.policy, CoopPolicy::UnsafeNone);
    }

    #[test]
    fn given_policy_text_when_policy_from_str_then_updates_to_parsed_policy() {
        let options = CoopOptions::new()
            .policy_from_str("same-origin-allow-popups")
            .expect("parse should succeed");

        assert_eq!(options.policy, CoopPolicy::SameOriginAllowPopups);
    }

    #[test]
    fn given_invalid_text_when_policy_from_str_then_returns_invalid_policy_error() {
        let error = CoopOptions::new()
            .policy_from_str("unknown")
            .expect_err("expected invalid policy error");

        assert_eq!(
            error,
            CoopOptionsError::InvalidPolicy("unknown".to_string())
        );
    }

    #[test]
    fn given_policy_text_when_from_policy_str_then_creates_options_with_policy() {
        let options = CoopOptions::from_policy_str("unsafe-none").expect("parse should succeed");

        assert_eq!(options.policy, CoopPolicy::UnsafeNone);
    }

    #[test]
    fn given_invalid_text_when_from_policy_str_then_returns_invalid_policy_error() {
        let error = CoopOptions::from_policy_str("bad").expect_err("expected invalid policy error");

        assert_eq!(error, CoopOptionsError::InvalidPolicy("bad".to_string()));
    }
}

mod validate {
    use super::*;

    #[test]
    fn given_any_options_when_validate_then_returns_ok() {
        let options = CoopOptions::new().policy(CoopPolicy::UnsafeNone);

        let result = options.validate();

        assert!(result.is_ok());
    }
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Randomly change the case of alphabetic characters in a token
    fn randomize_case(input: &str, toggles: &[bool]) -> String {
        input
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c.is_ascii_alphabetic() {
                    if toggles.get(i).copied().unwrap_or(false) {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                } else {
                    c
                }
            })
            .collect()
    }

    proptest! {
        #[test]
        fn given_random_padding_and_casing_when_parse_then_returns_expected_policy(
            // choose a base token
            which in 0u8..3u8,
            // random toggles for case changes, over-allocate length for safety
            toggles in proptest::collection::vec(any::<bool>(), 0..64),
            // left/right padding with whitespace chars
            left_pad in proptest::collection::vec(prop_oneof![Just(' '), Just('\t'), Just('\n'), Just('\r')], 0..4),
            right_pad in proptest::collection::vec(prop_oneof![Just(' '), Just('\t'), Just('\n'), Just('\r')], 0..4),
        ) {
            let (base, expected) = match which {
                0 => ("same-origin", CoopPolicy::SameOrigin),
                1 => ("same-origin-allow-popups", CoopPolicy::SameOriginAllowPopups),
                _ => ("unsafe-none", CoopPolicy::UnsafeNone),
            };

            let randomized = randomize_case(base, &toggles);
            let left: String = left_pad.into_iter().collect();
            let right: String = right_pad.into_iter().collect();
            let input = format!("{left}{randomized}{right}");

            let parsed: CoopPolicy = input.parse().expect("parse should succeed");
            prop_assert_eq!(parsed, expected);
        }
    }
}
