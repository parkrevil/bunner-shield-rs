use std::collections::HashSet;

use crate::csp::options::{
    builders::{ScriptSrcBuilder, StyleSrcBuilder, TrustedTypesBuilder},
    sandbox::SandboxToken,
    sources::CspSource,
    types::CspDirective,
    utils::contains_token,
};

use super::ReportToMergeStrategy;
use super::core::CspOptions;
use crate::executor::PolicyMode;

impl CspOptions {
    pub fn default_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::DefaultSrc, sources);
        self
    }

    pub fn script_src<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(ScriptSrcBuilder<'_>) -> ScriptSrcBuilder<'_>,
    {
        let builder = ScriptSrcBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub fn style_src<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(StyleSrcBuilder<'_>) -> StyleSrcBuilder<'_>,
    {
        let builder = StyleSrcBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub fn img_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ImgSrc, sources);
        self
    }

    pub fn connect_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ConnectSrc, sources);
        self
    }

    pub fn font_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FontSrc, sources);
        self
    }

    pub fn frame_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FrameSrc, sources);
        self
    }

    pub fn worker_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::WorkerSrc, sources);
        self
    }

    pub fn navigate_to<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::NavigateTo, sources);
        self
    }

    pub fn object_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ObjectSrc, sources);
        self
    }

    pub fn media_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::MediaSrc, sources);
        self
    }

    pub fn manifest_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ManifestSrc, sources);
        self
    }

    pub fn frame_ancestors<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FrameAncestors, sources);
        self
    }

    pub fn base_uri<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::BaseUri, sources);
        self
    }

    pub fn form_action<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::FormAction, sources);
        self
    }

    pub fn trusted_types<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(TrustedTypesBuilder<'_>) -> TrustedTypesBuilder<'_>,
    {
        let builder = TrustedTypesBuilder::new(&mut self);
        let _ = configure(builder);
        self
    }

    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.set_flag_directive(CspDirective::UpgradeInsecureRequests);
        self
    }

    pub fn block_all_mixed_content(mut self) -> Self {
        self.set_flag_directive(CspDirective::BlockAllMixedContent);
        self
    }

    pub fn report_only(mut self) -> Self {
        self.mode = PolicyMode::ReportOnly;
        self
    }

    pub fn sandbox(mut self) -> Self {
        self.set_flag_directive(CspDirective::Sandbox);
        self
    }

    pub fn sandbox_with<I>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = SandboxToken>,
    {
        let mut rendered = Vec::new();
        let mut seen = HashSet::new();

        for token in tokens.into_iter() {
            let value = token.as_str();
            if seen.insert(value) {
                rendered.push(value);
            }
        }

        let value = rendered.join(" ");
        self.set_directive(CspDirective::Sandbox.as_str(), &value);
        self
    }

    pub fn report_to(mut self, group: impl Into<String>) -> Self {
        let value = group.into().trim().to_string();
        self.set_directive(CspDirective::ReportTo.as_str(), &value);
        self
    }

    pub fn add_source<S>(mut self, directive: CspDirective, source: S) -> Self
    where
        S: Into<CspSource>,
    {
        let token_string = source.into().to_string();
        let trimmed = token_string.trim();

        if trimmed.is_empty() {
            return self;
        }

        self.add_directive_token(directive.as_str(), trimmed);
        self
    }

    pub fn merge(mut self, other: &CspOptions) -> Self {
        for (name, value) in &other.directives {
            if name == CspDirective::ReportTo.as_str() {
                match self.report_to_merge_strategy {
                    ReportToMergeStrategy::FirstWins => {
                        if self.directives.iter().all(|(existing, _)| existing != name) {
                            self.set_directive(name, value);
                        }
                    }
                    ReportToMergeStrategy::LastWins => {
                        // overwrite or set
                        let mut found = false;
                        for (existing, existing_value) in &mut self.directives {
                            if existing == name {
                                *existing_value = value.clone();
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            self.set_directive(name, value);
                        }
                    }
                    ReportToMergeStrategy::Union => {
                        // order-preserving unique union with minimal allocations
                        let mut merged_tokens: Vec<String> = Vec::new();
                        let mut total_len = 0usize;

                        if let Some((_, existing_value)) = self
                            .directives
                            .iter()
                            .find(|(existing, _)| existing == name)
                        {
                            let existing_iter = existing_value.split_whitespace();
                            merged_tokens.reserve(existing_iter.clone().count());
                            for token in existing_iter {
                                if token.is_empty() {
                                    continue;
                                }
                                if merged_tokens.iter().any(|existing| existing == token) {
                                    continue;
                                }
                                total_len += token.len();
                                merged_tokens.push(token.to_string());
                            }
                        }

                        let incoming_iter = value.split_whitespace();
                        merged_tokens.reserve(incoming_iter.clone().count());
                        for token in incoming_iter {
                            if token.is_empty() {
                                continue;
                            }
                            if merged_tokens.iter().any(|existing| existing == token) {
                                continue;
                            }
                            total_len += token.len();
                            merged_tokens.push(token.to_string());
                        }

                        let merged = if merged_tokens.is_empty() {
                            String::new()
                        } else {
                            // account for spaces between tokens
                            total_len += merged_tokens.len().saturating_sub(1);
                            let mut result = String::with_capacity(total_len);
                            let mut tokens = merged_tokens.iter();
                            if let Some(first) = tokens.next() {
                                result.push_str(first);
                            }
                            for token in tokens {
                                result.push(' ');
                                result.push_str(token);
                            }
                            result
                        };

                        let mut updated = false;
                        for (existing, existing_value) in &mut self.directives {
                            if existing == name {
                                *existing_value = merged.clone();
                                updated = true;
                                break;
                            }
                        }
                        if !updated {
                            self.set_directive(name, &merged);
                        }
                    }
                }
                continue;
            }

            let trimmed = value.trim();
            if trimmed.is_empty() {
                if self.directives.iter().all(|(existing, _)| existing != name) {
                    self.set_directive(name, value);
                }
                continue;
            }

            if let Some((_, existing_value)) = self
                .directives
                .iter_mut()
                .find(|(existing, _)| existing == name)
            {
                let mut pending: Vec<&str> = Vec::new();
                for token in trimmed.split_whitespace() {
                    if token.is_empty() {
                        continue;
                    }
                    if contains_token(existing_value, token) {
                        continue;
                    }
                    if pending.iter().any(|existing| existing == &token) {
                        continue;
                    }
                    pending.push(token);
                }

                if pending.is_empty() {
                    continue;
                }

                let mut extra_capacity: usize = pending.iter().map(|token| token.len()).sum();
                let mut needs_space = !existing_value.trim().is_empty();
                let spaces = if needs_space {
                    pending.len()
                } else {
                    pending.len().saturating_sub(1)
                };
                extra_capacity += spaces;
                existing_value.reserve(extra_capacity);

                for token in pending {
                    if needs_space {
                        existing_value.push(' ');
                    }
                    existing_value.push_str(token);
                    needs_space = true;
                }
            } else {
                self.set_directive(name, trimmed);
            }
        }

        self.merge_runtime_nonce(other);

        self
    }

    pub fn require_trusted_types_for_scripts(mut self) -> Self {
        self.set_directive(CspDirective::RequireTrustedTypesFor.as_str(), "'script'");
        self
    }
}

#[cfg(test)]
#[path = "builder_api_test.rs"]
mod builder_api_test;
