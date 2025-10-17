use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHeaders {
    entries: HashMap<String, HeaderEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderEntry {
    original: String,
    values: Vec<String>,
    joined: String,
    multi_value: bool,
}

impl HeaderEntry {
    fn new(original: String, multi_value: bool) -> Self {
        Self {
            original,
            values: Vec::new(),
            joined: String::new(),
            multi_value,
        }
    }

    fn update_joined(&mut self) {
        if self.multi_value {
            self.joined = self.values.join("\n");
        } else {
            self.joined = self.values.first().cloned().unwrap_or_default();
        }
    }
}

impl NormalizedHeaders {
    pub fn new(origin_headers: HashMap<String, String>) -> Self {
        let mut normalized = Self {
            entries: HashMap::new(),
        };

        for (name, value) in origin_headers {
            normalized.insert(name, value);
        }

        normalized
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let original = name.into();
        let normalized = original.to_ascii_lowercase();
        let multi_value = is_multi_value(&normalized);

        let values = if multi_value {
            split_multi_values(value.into())
        } else {
            vec![value.into()]
        };

        let entry = self
            .entries
            .entry(normalized)
            .or_insert_with(|| HeaderEntry::new(original.clone(), multi_value));

        entry.original = original;
        if entry.multi_value {
            entry.values.extend(values);
        } else {
            entry.values = values;
        }
        entry.update_joined();
    }

    pub fn remove(&mut self, name: &str) {
        let normalized = name.to_ascii_lowercase();
        self.entries.remove(&normalized);
    }

    pub fn get_all(&self, name: &str) -> Option<&[String]> {
        let normalized = name.to_ascii_lowercase();
        self.entries
            .get(&normalized)
            .map(|entry| entry.values.as_slice())
    }

    pub fn into_result(self) -> HashMap<String, String> {
        self.entries
            .into_values()
            .map(|entry| (entry.original, entry.joined))
            .collect()
    }
}

fn is_multi_value(name: &str) -> bool {
    matches!(name, "set-cookie")
}

fn split_multi_values(raw: String) -> Vec<String> {
    raw.split(['\n', '\r'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if let Some(stripped) = segment.strip_prefix("Set-Cookie:") {
                stripped.trim().to_string()
            } else {
                segment.to_string()
            }
        })
        .collect()
}
