use crate::executor::FeatureOptions;
use std::borrow::Cow;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsPolicyOptions {
    policy: String,
}

impl PermissionsPolicyOptions {
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
        }
    }

    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = policy.into();
        self
    }

    pub(crate) fn header_value(&self) -> &str {
        self.policy.as_str()
    }

    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionsPolicyOptionsError {
    #[error("permissions policy value must not be empty")]
    EmptyPolicy,
}

impl FeatureOptions for PermissionsPolicyOptions {
    type Error = PermissionsPolicyOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.policy.trim().is_empty() {
            Err(PermissionsPolicyOptionsError::EmptyPolicy)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;

#[derive(Debug, Default)]
pub struct PolicyBuilder {
    entries: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowListItem<'a> {
    None,
    SelfKeyword,
    Any, // "*" only for some features, but we keep minimal semantics here
    Origin(Cow<'a, str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    feature: String,
    allowlist: Vec<String>, // normalized and owned rendered items
}

impl PolicyBuilder {
    pub fn feature<'a, I>(mut self, name: impl Into<String>, allowlist: I) -> Self
    where
        I: IntoIterator<Item = AllowListItem<'a>>,
    {
        let feature = name.into().trim().to_ascii_lowercase();
        if feature.is_empty() {
            return self; // ignore empty feature names
        }

        let mut seen = std::collections::HashSet::new();
        let mut list: Vec<String> = Vec::new();
        for item in allowlist.into_iter() {
            let rendered: Option<String> = match item {
                AllowListItem::None => Some("()".to_string()),
                AllowListItem::SelfKeyword => Some("self".to_string()),
                AllowListItem::Any => Some("*".to_string()),
                AllowListItem::Origin(s) => {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
            };

            if let Some(token) = rendered {
                // preserve first-seen order: only push if not seen yet
                if !seen.contains(&token) {
                    seen.insert(token.clone());
                    list.push(token);
                }
            }
        }

        self.entries.push(PolicyEntry {
            feature,
            allowlist: list,
        });
        self
    }

    pub fn build(self) -> PermissionsPolicyOptions {
        // Render entries in insertion order: feature=(items) separated by commas; items by spaces
        let mut parts: Vec<String> = Vec::with_capacity(self.entries.len());
        for entry in self.entries {
            let mut items: Vec<String> = Vec::with_capacity(entry.allowlist.len());
            for item in entry.allowlist {
                items.push(item);
            }
            let rendered = if items.is_empty() {
                format!("{}=()", entry.feature)
            } else {
                format!("{}=({})", entry.feature, items.join(" "))
            };
            parts.push(rendered);
        }

        let policy = parts.join(", ");
        PermissionsPolicyOptions::new(policy)
    }
}
