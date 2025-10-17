use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHeaders {
    entries: HashMap<String, HeaderEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderEntry {
    original: String,
    values: Vec<Cow<'static, str>>,
    joined: Cow<'static, str>,
    multi_value: bool,
}

impl HeaderEntry {
    fn new(original: String, multi_value: bool) -> Self {
        Self {
            original,
            values: Vec::new(),
            joined: Cow::Borrowed(""),
            multi_value,
        }
    }

    fn update_joined(&mut self) {
        if self.multi_value {
            let joined = self
                .values
                .iter()
                .map(|value| value.as_ref())
                .collect::<Vec<_>>()
                .join("\n");
            self.joined = Cow::Owned(joined);
        } else {
            self.joined = self.values.first().cloned().unwrap_or(Cow::Borrowed(""));
        }
    }
}

impl NormalizedHeaders {
    pub fn new(origin_headers: HashMap<String, String>) -> Self {
        let mut normalized = Self {
            entries: HashMap::with_capacity(origin_headers.len()),
        };

        for (name, value) in origin_headers {
            normalized.insert(name, value);
        }

        normalized
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Cow<'static, str>>) {
        let original = name.into();
        let normalized = original.to_ascii_lowercase();
        let multi_value = is_multi_value(&normalized);

        let value = value.into();
        let values = if multi_value {
            split_multi_values(value.into_owned())
        } else {
            vec![value]
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

    pub fn insert_owned(&mut self, name: impl Into<String>, value: String) {
        self.insert(name, Cow::Owned(value));
    }

    pub fn remove(&mut self, name: &str) {
        let normalized = name.to_ascii_lowercase();
        self.entries.remove(&normalized);
    }

    pub fn get_all(&self, name: &str) -> Option<&[Cow<'static, str>]> {
        let normalized = name.to_ascii_lowercase();
        self.entries
            .get(&normalized)
            .map(|entry| entry.values.as_slice())
    }

    pub fn into_result(self) -> HashMap<String, String> {
        self.entries
            .into_values()
            .map(|entry| (entry.original, entry.joined.into_owned()))
            .collect()
    }
}

fn is_multi_value(name: &str) -> bool {
    matches!(name, "set-cookie")
}

fn split_multi_values(raw: String) -> Vec<Cow<'static, str>> {
    raw.split(['\n', '\r'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if let Some(stripped) = segment.strip_prefix("Set-Cookie:") {
                Cow::Owned(stripped.trim().to_string())
            } else {
                Cow::Owned(segment.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "normalized_headers_test.rs"]
mod normalized_headers_test;
