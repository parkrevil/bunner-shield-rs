use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHeaders {
    entries: HashMap<String, HeaderEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderEntry {
    original: String,
    value: String,
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
        let value = value.into();

        self.entries
            .insert(normalized, HeaderEntry { original, value });
    }

    pub fn remove(&mut self, name: &str) {
        let normalized = name.to_ascii_lowercase();
        self.entries.remove(&normalized);
    }

    pub fn into_result(self) -> HashMap<String, String> {
        self.entries
            .into_values()
            .map(|entry| (entry.original, entry.value))
            .collect()
    }
}
