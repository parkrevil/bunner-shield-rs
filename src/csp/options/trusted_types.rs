use std::collections::HashSet;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustedTypesPolicy {
    name: String,
}

impl TrustedTypesPolicy {
    pub fn new(name: impl Into<String>) -> Result<Self, TrustedTypesPolicyError> {
        let name = name.into();
        if name.is_empty() {
            return Err(TrustedTypesPolicyError::Empty);
        }

        if !Self::is_valid(&name) {
            return Err(TrustedTypesPolicyError::InvalidName(name));
        }

        Ok(Self { name })
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }

    pub fn into_string(self) -> String {
        self.name
    }

    fn is_valid(value: &str) -> bool {
        let mut chars = value.chars();

        match chars.next() {
            Some(first) if first.is_ascii_alphabetic() => {}
            _ => return false,
        }

        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrustedTypesToken {
    Policy(TrustedTypesPolicy),
    AllowDuplicates,
}

impl TrustedTypesToken {
    pub fn policy(policy: TrustedTypesPolicy) -> Self {
        Self::Policy(policy)
    }

    pub fn allow_duplicates() -> Self {
        Self::AllowDuplicates
    }

    pub fn into_string(self) -> String {
        match self {
            TrustedTypesToken::Policy(policy) => policy.into_string(),
            TrustedTypesToken::AllowDuplicates => "'allow-duplicates'".to_string(),
        }
    }
}

impl From<TrustedTypesPolicy> for TrustedTypesToken {
    fn from(policy: TrustedTypesPolicy) -> Self {
        TrustedTypesToken::Policy(policy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrustedTypesPolicyError {
    #[error("trusted types policy must not be empty")]
    Empty,
    #[error("trusted types policy `{0}` contains invalid characters")]
    InvalidName(String),
}

pub(crate) fn render_tokens(tokens: impl IntoIterator<Item = TrustedTypesToken>) -> String {
    let mut rendered: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for token in tokens.into_iter() {
        let value = token.into_string();
        if seen.insert(value.clone()) {
            rendered.push(value);
        }
    }

    rendered.join(" ")
}

#[cfg(test)]
#[path = "trusted_types_test.rs"]
mod trusted_types_test;
