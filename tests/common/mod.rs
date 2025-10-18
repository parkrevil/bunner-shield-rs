use bunner_shield_rs::NormalizedHeaders;
use std::collections::HashMap;

pub fn empty_headers() -> HashMap<String, String> {
    HashMap::new()
}

pub fn headers_with(entries: &[(&str, &str)]) -> HashMap<String, String> {
    let mut headers = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        headers.insert((*key).to_string(), (*value).to_string());
    }
    headers
}

pub fn normalized_headers_from(entries: &[(&str, &str)]) -> NormalizedHeaders {
    NormalizedHeaders::new(headers_with(entries))
}
