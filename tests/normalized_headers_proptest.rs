use bunner_shield_rs::NormalizedHeaders;
use proptest::prelude::*;
use proptest::prop_oneof;
use std::collections::{HashMap, HashSet};

fn header_name_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9-]{1,16}").unwrap()
}

fn header_value_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[ -~]{0,48}").unwrap()
}

fn cookie_line_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        header_value_strategy(),
        header_value_strategy().prop_map(|line| format!("Set-Cookie: {}", line))
    ]
}

fn expected_normalized_headers_output(entries: &[(String, String)]) -> HashMap<String, String> {
    let mut state: HashMap<String, (String, Vec<String>, bool)> = HashMap::new();

    for (name, value) in entries {
        let normalized = name.to_ascii_lowercase();
        let multi_value = normalized == "set-cookie";

        let values = if multi_value {
            value
                .split(['\n', '\r'])
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(|segment| {
                    if let Some(stripped) = segment.strip_prefix("Set-Cookie:") {
                        stripped.trim().to_string()
                    } else {
                        segment.to_string()
                    }
                })
                .collect::<Vec<_>>()
        } else {
            vec![value.clone()]
        };

        let entry = state
            .entry(normalized)
            .or_insert_with(|| (name.clone(), Vec::new(), multi_value));

        entry.0 = name.clone();
        entry.2 = multi_value;
        if entry.2 {
            entry.1.extend(values);
        } else {
            entry.1 = values;
        }
    }

    state
        .into_values()
        .map(|(original, values, multi)| {
            let joined = if multi {
                values.join("\n")
            } else {
                values.first().cloned().unwrap_or_default()
            };
            (original, joined)
        })
        .collect()
}

proptest! {
    #[test]
    fn normalized_headers_proptest_inserting_headers_is_order_independent(entries in prop::collection::vec((header_name_strategy(), header_value_strategy()), 0..12)) {
        let mut headers = NormalizedHeaders::new(HashMap::new());

        for (name, value) in &entries {
            headers.insert(name.clone(), value.clone());
        }

        let actual = headers.into_result();
        let expected = expected_normalized_headers_output(&entries);

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn normalized_headers_proptest_set_cookie_multi_value_splits_on_newlines(lines in prop::collection::vec(cookie_line_strategy(), 0..6)) {
        let mut headers = NormalizedHeaders::new(HashMap::new());
        let joined = lines.join("\n");

        headers.insert("Set-Cookie", joined);

        let actual: Vec<String> = headers
            .get_all("Set-Cookie")
            .map(|values| values.iter().map(|value| value.to_string()).collect())
            .unwrap_or_default();

        let expected: Vec<String> = lines
            .iter()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else if let Some(rest) = trimmed.strip_prefix("Set-Cookie:") {
                    Some(rest.trim().to_string())
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn normalized_headers_proptest_removing_header_is_case_insensitive(seed in prop::collection::hash_map(header_name_strategy(), header_value_strategy(), 0..12), remove_name in header_name_strategy()) {
        let mut headers = NormalizedHeaders::new(seed);

        headers.remove(remove_name.as_str());

        prop_assert!(headers.get_all(remove_name.as_str()).is_none());
    }

    #[test]
    fn normalized_headers_proptest_roundtrip_is_idempotent(entries in prop::collection::vec((header_name_strategy(), header_value_strategy()), 0..16)) {
        let mut headers = NormalizedHeaders::new(HashMap::new());

        for (name, value) in &entries {
            headers.insert(name.clone(), value.clone());
        }

        let first_pass = headers.into_result();
        let round_tripped = NormalizedHeaders::new(first_pass.clone()).into_result();

        prop_assert_eq!(round_tripped, first_pass);
    }

    #[test]
    fn normalized_headers_proptest_case_insensitive_views(entries in prop::collection::vec((header_name_strategy(), header_value_strategy()), 0..16)) {
        let mut headers = NormalizedHeaders::new(HashMap::new());

        for (name, value) in &entries {
            headers.insert(name.clone(), value.clone());
        }

        for (name, _) in &entries {
            if headers.get_all(name).is_none() {
                continue;
            }

            let lower = name.to_ascii_lowercase();
            let upper = name.to_ascii_uppercase();
            let alternating: String = name
                .chars()
                .enumerate()
                .map(|(idx, ch)| if idx % 2 == 0 {
                    ch.to_ascii_lowercase()
                } else {
                    ch.to_ascii_uppercase()
                })
                .collect();

            let canonical = headers.get_all(&lower).map(|values| values.to_vec());
            let upper_values = headers.get_all(&upper).map(|values| values.to_vec());
            let alternating_values = headers.get_all(&alternating).map(|values| values.to_vec());
            let original_values = headers.get_all(name.as_str()).map(|values| values.to_vec());

            prop_assert_eq!(upper_values, canonical.clone());
            prop_assert_eq!(alternating_values, canonical.clone());
            prop_assert_eq!(original_values, canonical);
        }
    }

    #[test]
    fn normalized_headers_proptest_remove_then_merge_matches_filtered(entries in prop::collection::vec((header_name_strategy(), header_value_strategy()), 0..16), remove_names in prop::collection::vec(header_name_strategy(), 0..8)) {
        let mut headers = NormalizedHeaders::new(HashMap::new());

        for (name, value) in &entries {
            headers.insert(name.clone(), value.clone());
        }

        for name in &remove_names {
            headers.remove(name);
        }

        let actual = headers.into_result();
        let removal_keys: HashSet<String> = remove_names
            .into_iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();

        let expected_entries: Vec<(String, String)> = entries
            .into_iter()
            .filter(|(name, _)| !removal_keys.contains(&name.to_ascii_lowercase()))
            .collect();
        let expected = expected_normalized_headers_output(&expected_entries);

        prop_assert_eq!(actual, expected);
    }
}
