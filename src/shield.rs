use crate::normalized_headers::NormalizedHeaders;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Shield;

impl Shield {
    pub fn new() -> Self {
        Self
    }

    pub fn secure(&self, headers: Vec<(String, String)>) -> NormalizedHeaders {
        NormalizedHeaders::from_pairs(headers)
    }
}

#[cfg(test)]
#[path = "shield_test.rs"]
mod shield_test;
