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
        let raw_name = name.into();
        let Some(original) = sanitize_header_name(&raw_name) else {
            return;
        };

        let normalized = original.to_ascii_lowercase();
        let multi_value = is_multi_value(&normalized);

        let value: Cow<'static, str> = value.into();
        let mut values: Vec<Cow<'static, str>> = if multi_value {
            split_multi_values(value.into_owned())
        } else {
            vec![value]
        };

        for segment in &mut values {
            if let Some(clean) = sanitize_header_value(segment.as_ref()) {
                *segment = Cow::Owned(clean);
            }
        }

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

    pub(crate) fn sanitize_for_http(&mut self) {
        let mut renames: Vec<(String, Option<String>)> = Vec::new();

        for (normalized_name, entry) in self.entries.iter_mut() {
            if entry.values.is_empty() {
                if let Some(clean) = sanitize_header_name(&entry.original) {
                    if clean != entry.original {
                        entry.original = clean;
                        renames.push((normalized_name.clone(), Some(entry.original.clone())));
                    }
                } else {
                    renames.push((normalized_name.clone(), None));
                }
                continue;
            }

            let mut mutated = false;
            let mut sanitized_values: Vec<Cow<'static, str>> =
                Vec::with_capacity(entry.values.len());

            for value in entry.values.iter() {
                if let Some(sanitized) = sanitize_header_value(value.as_ref()) {
                    sanitized_values.push(Cow::Owned(sanitized));
                    mutated = true;
                } else {
                    sanitized_values.push(value.clone());
                }
            }

            if mutated {
                entry.values = sanitized_values;
                entry.update_joined();
            }

            if let Some(clean) = sanitize_header_name(&entry.original) {
                if clean != entry.original {
                    entry.original = clean;
                    renames.push((normalized_name.clone(), Some(entry.original.clone())));
                }
            } else {
                renames.push((normalized_name.clone(), None));
            }
        }

        for (old_key, target_name) in renames {
            match target_name {
                Some(new_original) => {
                    let new_key = new_original.to_ascii_lowercase();
                    if new_key == old_key {
                        if let Some(entry) = self.entries.get_mut(&old_key) {
                            entry.multi_value = is_multi_value(&new_key);
                            entry.update_joined();
                        }
                        continue;
                    }

                    if let Some(mut entry) = self.entries.remove(&old_key) {
                        entry.original = new_original.clone();
                        entry.multi_value = is_multi_value(&new_key);
                        entry.update_joined();
                        self.entries.insert(new_key, entry);
                    }
                }
                None => {
                    self.entries.remove(&old_key);
                }
            }
        }
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

fn sanitize_header_value(value: &str) -> Option<String> {
    let mut sanitized = String::with_capacity(value.len());
    let mut changed = false;
    let mut last_was_space = false;

    for ch in value.chars() {
        if ch.is_control() {
            if !last_was_space {
                sanitized.push(' ');
                last_was_space = true;
            }
            changed = true;
            continue;
        }

        if ch.is_whitespace() && ch != ' ' {
            if !last_was_space {
                sanitized.push(' ');
                last_was_space = true;
            }
            if ch != ' ' {
                changed = true;
            }
            continue;
        }

        sanitized.push(ch);
        last_was_space = ch == ' ';
    }

    if changed { Some(sanitized) } else { None }
}

fn sanitize_header_name(name: &str) -> Option<String> {
    let mut sanitized = String::with_capacity(name.len());
    let mut changed = false;

    for ch in name.chars() {
        if is_token_char(ch) {
            sanitized.push(ch);
        } else {
            changed = true;
        }
    }

    if sanitized.is_empty() {
        return None;
    }

    if changed {
        Some(sanitized)
    } else {
        Some(name.to_string())
    }
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

#[cfg(test)]
#[path = "normalized_headers_test.rs"]
mod normalized_headers_test;
