#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHeaders {
    entries: Vec<HeaderEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderEntry {
    normalized: String,
    original: String,
    value: String,
}

impl NormalizedHeaders {
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let entries = pairs
            .into_iter()
            .map(|(name, value)| HeaderEntry {
                normalized: name.to_ascii_lowercase(),
                original: name,
                value,
            })
            .collect();

        Self { entries }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let target = name.to_ascii_lowercase();

        self.entries
            .iter()
            .find(|entry| entry.normalized == target)
            .map(|entry| entry.value.as_str())
    }
}

#[cfg(test)]
#[path = "normalized_headers_test.rs"]
mod normalized_headers_test;
