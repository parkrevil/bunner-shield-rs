use std::collections::HashSet;

use crate::csp::options::{
    builders::{ScriptSrcBuilder, StyleSrcBuilder, TrustedTypesBuilder},
    sandbox::SandboxToken,
    sources::CspSource,
    types::CspDirective,
};

use super::core::CspOptions;

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
                if self.directives.iter().all(|(existing, _)| existing != name) {
                    self.set_directive(name, value);
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

            for token in trimmed.split_whitespace() {
                self.add_directive_token(name, token);
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
