use crate::constants::header_values::{
    CLEAR_SITE_DATA_CACHE, CLEAR_SITE_DATA_COOKIES, CLEAR_SITE_DATA_EXECUTION_CONTEXTS,
    CLEAR_SITE_DATA_STORAGE,
};
use crate::executor::FeatureOptions;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClearSiteDataOptions {
    cache: bool,
    cookies: bool,
    storage: bool,
    execution_contexts: bool,
}

impl ClearSiteDataOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cache(mut self) -> Self {
        self.cache = true;
        self
    }

    pub fn cookies(mut self) -> Self {
        self.cookies = true;
        self
    }

    pub fn storage(mut self) -> Self {
        self.storage = true;
        self
    }

    pub fn execution_contexts(mut self) -> Self {
        self.execution_contexts = true;
        self
    }

    pub(crate) fn header_value(&self) -> String {
        let mut sections = Vec::new();

        if self.cache {
            sections.push(CLEAR_SITE_DATA_CACHE);
        }
        if self.cookies {
            sections.push(CLEAR_SITE_DATA_COOKIES);
        }
        if self.storage {
            sections.push(CLEAR_SITE_DATA_STORAGE);
        }
        if self.execution_contexts {
            sections.push(CLEAR_SITE_DATA_EXECUTION_CONTEXTS);
        }

        sections.join(", ")
    }

    fn has_any_section(&self) -> bool {
        self.cache || self.cookies || self.storage || self.execution_contexts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearSiteDataOptionsError {
    NoSectionsSelected,
}

impl fmt::Display for ClearSiteDataOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearSiteDataOptionsError::NoSectionsSelected => {
                f.write_str("clear-site-data requires at least one section")
            }
        }
    }
}

impl std::error::Error for ClearSiteDataOptionsError {}

impl FeatureOptions for ClearSiteDataOptions {
    type Error = ClearSiteDataOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.has_any_section() {
            Ok(())
        } else {
            Err(ClearSiteDataOptionsError::NoSectionsSelected)
        }
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
