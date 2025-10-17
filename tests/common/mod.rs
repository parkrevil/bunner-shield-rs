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

pub fn into_owned_pairs(headers: HashMap<String, String>) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = headers.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}
