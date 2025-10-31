use bunner_shield_rs::{
    PermissionsPolicyOptions, PermissionsPolicyOptionsError, Shield, ShieldError,
};
use std::collections::HashMap;
mod common;
use common::empty_headers;
use proptest::prelude::*;

fn with_permissions_policy(value: &str) -> HashMap<String, String> {
    let mut headers = empty_headers();
    headers.insert("Permissions-Policy".to_string(), value.to_string());
    headers
}

fn assert_permissions_policy(actual: &str, expected: &[&str]) {
    let mut actual_tokens: Vec<_> = actual
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    let mut expected_tokens: Vec<_> = expected.to_vec();

    actual_tokens.sort_unstable();
    expected_tokens.sort_unstable();

    assert_eq!(actual_tokens, expected_tokens);
}

mod success {
    use super::*;

    #[test]
    fn given_policy_when_secure_then_sets_permissions_policy_header() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Permissions-Policy")
            .expect("permissions-policy header");

        assert_permissions_policy(header, &["geolocation=()"]);
    }

    #[test]
    fn given_policy_override_when_secure_then_applies_latest_value() {
        let options = PermissionsPolicyOptions::new("geolocation=()").policy("microphone=('self')");
        let shield = Shield::new().permissions_policy(options).expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Permissions-Policy")
            .expect("permissions-policy header");

        assert_permissions_policy(header, &["microphone=('self')"]);
    }

    #[test]
    fn given_multiple_features_when_secure_then_preserves_permissions_policy_formatting() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("camera=()"))
            .expect("feature")
            .x_content_type_options()
            .expect("xcto");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Permissions-Policy")
            .expect("permissions-policy header");

        assert_permissions_policy(header, &["camera=()"]);
    }

    #[test]
    fn given_multi_feature_policy_when_secure_then_keeps_original_layout() {
        let policy = "geolocation=(), microphone=('self'), camera=(), fullscreen=()";
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new(policy))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        let header = result
            .get("Permissions-Policy")
            .expect("permissions-policy header");

        assert_eq!(header, policy);
    }
}

mod report_only {
    use super::*;

    #[test]
    fn given_report_only_policy_when_secure_then_sets_only_report_only_header() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()").report_only())
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy-Report-Only"),
            Some(&"geolocation=()".to_string())
        );
        assert!(!result.contains_key("Permissions-Policy"));
        assert!(!result.contains_key("Feature-Policy"));
    }
}

mod edge {
    use super::*;

    #[test]
    fn given_existing_header_when_secure_then_overwrites_permissions_policy() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("camera=()"))
            .expect("feature");

        let result = shield
            .secure(with_permissions_policy("geolocation=()*"))
            .expect("secure");

        let header = result
            .get("Permissions-Policy")
            .expect("permissions-policy header");

        assert_permissions_policy(header, &["camera=()"]);
    }

    #[test]
    fn given_other_headers_when_secure_then_leaves_them_intact() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("geolocation=()"))
            .expect("feature");

        let mut headers = with_permissions_policy("camera=()");
        headers.insert("X-Other".to_string(), "value".to_string());

        let result = shield.secure(headers).expect("secure");

        assert_eq!(result.get("X-Other").map(String::as_str), Some("value"));
    }
}

mod sanitization {
    use super::*;

    #[test]
    fn given_incoming_policy_with_control_characters_when_secure_then_sanitizes_value() {
        let shield = Shield::new();
        let mut headers = empty_headers();
        headers.insert(
            "Permissions-Policy".to_string(),
            "camera=()\r\ngeolocation=()".to_string(),
        );

        let result = shield.secure(headers).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("camera=() geolocation=()"),
        );
    }

    #[test]
    fn given_feature_policy_with_control_characters_when_secure_then_emits_sanitized_header() {
        let shield = Shield::new()
            .permissions_policy(PermissionsPolicyOptions::new("camera=()\r\ngeolocation=()"))
            .expect("feature");

        let result = shield.secure(empty_headers()).expect("secure");

        assert_eq!(
            result.get("Permissions-Policy").map(String::as_str),
            Some("camera=() geolocation=()"),
        );
    }
}

mod failure {
    use super::*;

    fn expect_validation_error(
        result: Result<Shield, ShieldError>,
    ) -> PermissionsPolicyOptionsError {
        let err = match result {
            Err(ShieldError::ExecutorValidationFailed(err)) => err,
            Err(ShieldError::ExecutionFailed(err)) => {
                panic!("expected validation failure, got execution error: {err}")
            }
            Ok(_) => panic!("expected validation failure but feature was accepted"),
        };

        err.downcast::<PermissionsPolicyOptionsError>()
            .map(|boxed| *boxed)
            .unwrap_or_else(|err| panic!("unexpected error type: {err}"))
    }

    #[test]
    fn given_empty_policy_when_add_feature_then_returns_empty_policy_error() {
        let error = expect_validation_error(
            Shield::new().permissions_policy(PermissionsPolicyOptions::new("")),
        );

        assert!(matches!(error, PermissionsPolicyOptionsError::EmptyPolicy));
    }

    #[test]
    fn given_whitespace_policy_when_add_feature_then_returns_empty_policy_error() {
        let error = expect_validation_error(
            Shield::new().permissions_policy(PermissionsPolicyOptions::new("   \t  ")),
        );

        assert!(matches!(error, PermissionsPolicyOptionsError::EmptyPolicy));
    }
}

mod proptests {
    use super::*;

    fn random_whitespace() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::bool::ANY, 0..3).prop_map(|flags| {
            flags
                .into_iter()
                .map(|is_space| if is_space { ' ' } else { '\t' })
                .collect()
        })
    }

    // Generate arbitrary non-target headers, avoiding the Permissions-Policy key.
    fn header_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        let name = prop::string::string_regex("[A-Za-z0-9-]{1,24}").unwrap();
        let value = prop::string::string_regex("[ -~]{0,64}").unwrap();

        prop::collection::vec((name, value), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .map(|(mut key, value)| {
                    if key.eq_ignore_ascii_case("Permissions-Policy") {
                        key.push_str("-alt");
                    }
                    (key, value)
                })
                .collect::<Vec<_>>()
        })
    }

    fn pp_case_strategy() -> impl Strategy<Value = String> {
        const HEADER_NAME: &str = "Permissions-Policy";
        prop::collection::vec(prop::bool::ANY, HEADER_NAME.len()).prop_map(|mask| {
            HEADER_NAME
                .chars()
                .zip(mask)
                .map(|(ch, lower)| {
                    if ch == '-' {
                        '-'
                    } else if lower {
                        ch.to_ascii_lowercase()
                    } else {
                        ch.to_ascii_uppercase()
                    }
                })
                .collect()
        })
    }

    #[derive(Clone, Debug)]
    enum AllowItemSpec {
        None,
        SelfKw,
        Any,
        Origin(String),
    }

    fn allow_item_strategy() -> impl Strategy<Value = AllowItemSpec> {
        let origin_core =
            prop::string::string_regex("https?://[A-Za-z0-9.-]{1,32}(:[0-9]{1,5})?").unwrap();
        let origin = (random_whitespace(), origin_core, random_whitespace())
            .prop_map(|(pre, core, post)| format!("{pre}{core}{post}"));

        prop_oneof![
            Just(AllowItemSpec::None),
            Just(AllowItemSpec::SelfKw),
            Just(AllowItemSpec::Any),
            origin.prop_map(AllowItemSpec::Origin),
        ]
    }

    #[derive(Clone, Debug)]
    struct FeatureSpec {
        name: String,
        allow: Vec<AllowItemSpec>,
    }

    fn feature_name_strategy() -> impl Strategy<Value = String> {
        // letters/digits/hyphens with optional surrounding whitespace (we'll lowercase in expected rendering)
        let core = prop::string::string_regex("[A-Za-z][A-Za-z0-9-]{0,15}").unwrap();
        (random_whitespace(), core, random_whitespace())
            .prop_map(|(pre, core, post)| format!("{pre}{core}{post}"))
    }

    fn features_strategy() -> impl Strategy<Value = Vec<FeatureSpec>> {
        prop::collection::vec(
            (
                feature_name_strategy(),
                prop::collection::vec(allow_item_strategy(), 0..6),
            )
                .prop_map(|(name, allow)| FeatureSpec { name, allow }),
            1..5,
        )
    }

    fn render_allow_item(spec: &AllowItemSpec) -> String {
        match spec {
            AllowItemSpec::None => "()".to_string(),
            AllowItemSpec::SelfKw => "self".to_string(),
            AllowItemSpec::Any => "*".to_string(),
            AllowItemSpec::Origin(s) => s.trim().to_string(),
        }
    }

    fn expected_policy(specs: &[FeatureSpec]) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(specs.len());
        for spec in specs {
            let feature = spec.name.trim().to_ascii_lowercase();
            let mut seen = std::collections::HashSet::new();
            let mut items: Vec<String> = Vec::new();
            for item in &spec.allow {
                let token = render_allow_item(item);
                if token.is_empty() {
                    continue;
                }
                if !seen.contains(&token) {
                    seen.insert(token.clone());
                    items.push(token);
                }
            }
            let rendered = if items.is_empty() {
                format!("{}=()", feature)
            } else {
                format!("{}=({})", feature, items.join(" "))
            };
            parts.push(rendered);
        }
        parts.join(", ")
    }

    proptest! {
        #[test]
        fn given_random_policy_when_secure_then_sets_header_idempotently(
            specs in features_strategy()
        ) {
            let expected = expected_policy(&specs);
            let options = PermissionsPolicyOptions::new(expected.clone());
            let shield = Shield::new().permissions_policy(options).expect("feature");
            let once = shield.secure(empty_headers()).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected_map = empty_headers();
            expected_map.insert("Permissions-Policy".to_string(), expected);

            prop_assert_eq!(once, expected_map.clone());
            prop_assert_eq!(twice, expected_map);
        }
    }

    fn two_distinct_pp_cases_strategy() -> impl Strategy<Value = (String, String)> {
        (pp_case_strategy(), pp_case_strategy())
            .prop_filter("distinct case variants", |(a, b)| a != b)
    }

    fn dedup_case_insensitive(entries: Vec<(String, String)>) -> Vec<(String, String)> {
        use std::collections::HashMap as StdHashMap;
        let mut map: StdHashMap<String, (String, String)> = StdHashMap::new();
        for (name, value) in entries {
            map.insert(name.to_ascii_lowercase(), (name, value));
        }
        map.into_values().collect()
    }

    proptest! {
        #[test]
        fn given_duplicate_case_variants_when_secure_then_collapses_and_canonicalizes(
            baseline in header_entries_strategy(),
            specs in features_strategy(),
            dup_cases in two_distinct_pp_cases_strategy(),
            values in (prop::string::string_regex("[ -~]{0,96}").unwrap(), prop::string::string_regex("[ -~]{0,96}").unwrap()),
        ) {
            let baseline = dedup_case_insensitive(baseline);
            let mut headers = empty_headers();
            for (name, value) in &baseline {
                headers.insert(name.clone(), value.clone());
            }
            // insert two differently-cased Permissions-Policy entries to simulate duplicates
            headers.insert(dup_cases.0.clone(), values.0.clone());
            headers.insert(dup_cases.1.clone(), values.1.clone());

            let options = PermissionsPolicyOptions::new(expected_policy(&specs));
            let expected_value = expected_policy(&specs);
            let shield = Shield::new().permissions_policy(options).expect("feature");
            let once = shield.secure(headers).expect("secure");
            let twice = shield.secure(once.clone()).expect("secure");

            let mut expected_map = baseline.into_iter().collect::<HashMap<_,_>>();
            expected_map.insert("Permissions-Policy".to_string(), expected_value);

            prop_assert_eq!(once, expected_map.clone());
            prop_assert_eq!(twice, expected_map);
        }
    }
}
