use crate::executor::FeatureOptions;
use base64::Engine;
use base64::engine::general_purpose;
use rand::RngCore;
use rand::rngs::OsRng;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl CspHashAlgorithm {
    fn prefix(self) -> &'static str {
        match self {
            CspHashAlgorithm::Sha256 => "sha256-",
            CspHashAlgorithm::Sha384 => "sha384-",
            CspHashAlgorithm::Sha512 => "sha512-",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspDirective {
    BaseUri,
    BlockAllMixedContent,
    ConnectSrc,
    DefaultSrc,
    FontSrc,
    FormAction,
    FrameAncestors,
    FrameSrc,
    ImgSrc,
    ManifestSrc,
    MediaSrc,
    NavigateTo,
    ObjectSrc,
    ReportTo,
    Sandbox,
    ScriptSrc,
    ScriptSrcAttr,
    ScriptSrcElem,
    StyleSrc,
    StyleSrcAttr,
    StyleSrcElem,
    TrustedTypes,
    RequireTrustedTypesFor,
    UpgradeInsecureRequests,
    WorkerSrc,
}

impl CspDirective {
    pub const ALL: [CspDirective; 25] = [
        CspDirective::BaseUri,
        CspDirective::BlockAllMixedContent,
        CspDirective::ConnectSrc,
        CspDirective::DefaultSrc,
        CspDirective::FontSrc,
        CspDirective::FormAction,
        CspDirective::FrameAncestors,
        CspDirective::FrameSrc,
        CspDirective::ImgSrc,
        CspDirective::ManifestSrc,
        CspDirective::MediaSrc,
        CspDirective::NavigateTo,
        CspDirective::ObjectSrc,
        CspDirective::ReportTo,
        CspDirective::Sandbox,
        CspDirective::ScriptSrc,
        CspDirective::ScriptSrcAttr,
        CspDirective::ScriptSrcElem,
        CspDirective::StyleSrc,
        CspDirective::StyleSrcAttr,
        CspDirective::StyleSrcElem,
        CspDirective::TrustedTypes,
        CspDirective::RequireTrustedTypesFor,
        CspDirective::UpgradeInsecureRequests,
        CspDirective::WorkerSrc,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CspDirective::BaseUri => "base-uri",
            CspDirective::BlockAllMixedContent => "block-all-mixed-content",
            CspDirective::ConnectSrc => "connect-src",
            CspDirective::DefaultSrc => "default-src",
            CspDirective::FontSrc => "font-src",
            CspDirective::FormAction => "form-action",
            CspDirective::FrameAncestors => "frame-ancestors",
            CspDirective::FrameSrc => "frame-src",
            CspDirective::ImgSrc => "img-src",
            CspDirective::ManifestSrc => "manifest-src",
            CspDirective::MediaSrc => "media-src",
            CspDirective::NavigateTo => "navigate-to",
            CspDirective::ObjectSrc => "object-src",
            CspDirective::ReportTo => "report-to",
            CspDirective::Sandbox => "sandbox",
            CspDirective::ScriptSrc => "script-src",
            CspDirective::ScriptSrcAttr => "script-src-attr",
            CspDirective::ScriptSrcElem => "script-src-elem",
            CspDirective::StyleSrc => "style-src",
            CspDirective::StyleSrcAttr => "style-src-attr",
            CspDirective::StyleSrcElem => "style-src-elem",
            CspDirective::TrustedTypes => "trusted-types",
            CspDirective::RequireTrustedTypesFor => "require-trusted-types-for",
            CspDirective::UpgradeInsecureRequests => "upgrade-insecure-requests",
            CspDirective::WorkerSrc => "worker-src",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspSource {
    SelfKeyword,
    None,
    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    WasmUnsafeEval,
    StrictDynamic,
    ReportSample,
    Wildcard,
    Scheme(Cow<'static, str>),
    Host(Cow<'static, str>),
    Nonce(String),
    Hash {
        algorithm: CspHashAlgorithm,
        value: String,
    },
    Custom(String),
}

impl CspSource {
    pub fn scheme(scheme: impl Into<Cow<'static, str>>) -> Self {
        Self::Scheme(scheme.into())
    }

    pub fn host(host: impl Into<Cow<'static, str>>) -> Self {
        Self::Host(host.into())
    }

    pub fn raw(value: impl Into<String>) -> Self {
        Self::Custom(value.into())
    }
}

impl fmt::Display for CspSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CspSource::SelfKeyword => f.write_str("'self'"),
            CspSource::None => f.write_str("'none'"),
            CspSource::UnsafeInline => f.write_str("'unsafe-inline'"),
            CspSource::UnsafeEval => f.write_str("'unsafe-eval'"),
            CspSource::UnsafeHashes => f.write_str("'unsafe-hashes'"),
            CspSource::WasmUnsafeEval => f.write_str("'wasm-unsafe-eval'"),
            CspSource::StrictDynamic => f.write_str("'strict-dynamic'"),
            CspSource::ReportSample => f.write_str("'report-sample'"),
            CspSource::Wildcard => f.write_str("*"),
            CspSource::Scheme(scheme) => write!(f, "{}:", scheme),
            CspSource::Host(host) => f.write_str(host),
            CspSource::Nonce(value) => {
                let sanitized = sanitize_token_input(value.clone());
                write!(f, "'nonce-{}'", sanitized)
            }
            CspSource::Hash { algorithm, value } => {
                let sanitized = sanitize_token_input(value.clone());
                write!(f, "'{}{}'", algorithm.prefix(), sanitized)
            }
            CspSource::Custom(value) => f.write_str(value),
        }
    }
}

impl From<&str> for CspSource {
    fn from(value: &str) -> Self {
        CspSource::Custom(value.to_string())
    }
}

impl From<String> for CspSource {
    fn from(value: String) -> Self {
        CspSource::Custom(value)
    }
}

impl From<CspNonce> for CspSource {
    fn from(nonce: CspNonce) -> Self {
        CspSource::Nonce(nonce.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxToken {
    AllowDownloads,
    AllowForms,
    AllowModals,
    AllowOrientationLock,
    AllowPointerLock,
    AllowPopups,
    AllowPopupsToEscapeSandbox,
    AllowPresentation,
    AllowSameOrigin,
    AllowScripts,
    AllowStorageAccessByUserActivation,
    AllowTopNavigation,
    AllowTopNavigationByUserActivation,
    AllowTopNavigationToCustomProtocols,
    AllowDownloadsWithoutUserActivation,
}

impl SandboxToken {
    fn as_str(self) -> &'static str {
        match self {
            SandboxToken::AllowDownloads => "allow-downloads",
            SandboxToken::AllowForms => "allow-forms",
            SandboxToken::AllowModals => "allow-modals",
            SandboxToken::AllowOrientationLock => "allow-orientation-lock",
            SandboxToken::AllowPointerLock => "allow-pointer-lock",
            SandboxToken::AllowPopups => "allow-popups",
            SandboxToken::AllowPopupsToEscapeSandbox => "allow-popups-to-escape-sandbox",
            SandboxToken::AllowPresentation => "allow-presentation",
            SandboxToken::AllowSameOrigin => "allow-same-origin",
            SandboxToken::AllowScripts => "allow-scripts",
            SandboxToken::AllowStorageAccessByUserActivation => {
                "allow-storage-access-by-user-activation"
            }
            SandboxToken::AllowTopNavigation => "allow-top-navigation",
            SandboxToken::AllowTopNavigationByUserActivation => {
                "allow-top-navigation-by-user-activation"
            }
            SandboxToken::AllowTopNavigationToCustomProtocols => {
                "allow-top-navigation-to-custom-protocols"
            }
            SandboxToken::AllowDownloadsWithoutUserActivation => {
                "allow-downloads-without-user-activation"
            }
        }
    }

    fn from_str(token: &str) -> Option<Self> {
        match token {
            "allow-downloads" => Some(SandboxToken::AllowDownloads),
            "allow-forms" => Some(SandboxToken::AllowForms),
            "allow-modals" => Some(SandboxToken::AllowModals),
            "allow-orientation-lock" => Some(SandboxToken::AllowOrientationLock),
            "allow-pointer-lock" => Some(SandboxToken::AllowPointerLock),
            "allow-popups" => Some(SandboxToken::AllowPopups),
            "allow-popups-to-escape-sandbox" => Some(SandboxToken::AllowPopupsToEscapeSandbox),
            "allow-presentation" => Some(SandboxToken::AllowPresentation),
            "allow-same-origin" => Some(SandboxToken::AllowSameOrigin),
            "allow-scripts" => Some(SandboxToken::AllowScripts),
            "allow-storage-access-by-user-activation" => {
                Some(SandboxToken::AllowStorageAccessByUserActivation)
            }
            "allow-top-navigation" => Some(SandboxToken::AllowTopNavigation),
            "allow-top-navigation-by-user-activation" => {
                Some(SandboxToken::AllowTopNavigationByUserActivation)
            }
            "allow-top-navigation-to-custom-protocols" => {
                Some(SandboxToken::AllowTopNavigationToCustomProtocols)
            }
            "allow-downloads-without-user-activation" => {
                Some(SandboxToken::AllowDownloadsWithoutUserActivation)
            }
            _ => None,
        }
    }
}

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

    fn into_string(self) -> String {
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CspOptions {
    pub(crate) directives: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspNonce {
    value: String,
}

impl CspNonce {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn header_value(&self) -> String {
        format!("'nonce-{}'", self.value)
    }

    pub fn into_inner(self) -> String {
        self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CspNonceManager {
    byte_len: usize,
}

impl CspNonceManager {
    pub fn new() -> Self {
        Self { byte_len: 32 }
    }

    pub fn with_size(byte_len: usize) -> Result<Self, CspNonceManagerError> {
        if byte_len == 0 {
            return Err(CspNonceManagerError::InvalidLength);
        }

        Ok(Self { byte_len })
    }

    pub fn issue(&self) -> CspNonce {
        let value = CspOptions::generate_nonce_with_size(self.byte_len);
        CspNonce { value }
    }

    pub fn issue_header_value(&self) -> String {
        self.issue().header_value()
    }

    pub fn byte_len(&self) -> usize {
        self.byte_len
    }
}

impl Default for CspNonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CspOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::DefaultSrc, sources);
        self
    }

    pub fn script_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ScriptSrc, sources);
        self
    }

    pub fn style_src<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::StyleSrc, sources);
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

    pub fn script_src_elem<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ScriptSrcElem, sources);
        self
    }

    pub fn script_src_attr<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::ScriptSrcAttr, sources);
        self
    }

    pub fn style_src_elem<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::StyleSrcElem, sources);
        self
    }

    pub fn style_src_attr<I, S>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        self.set_directive_sources(CspDirective::StyleSrcAttr, sources);
        self
    }

    pub fn trusted_types_tokens<I>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = TrustedTypesToken>,
    {
        let mut rendered: Vec<String> = Vec::new();
        let mut seen = HashSet::new();

        for token in tokens.into_iter() {
            let value = token.into_string();
            if seen.insert(value.clone()) {
                rendered.push(value);
            }
        }

        let value = rendered.join(" ");
        self.set_directive(CspDirective::TrustedTypes.as_str(), &value);
        self
    }

    pub fn trusted_types_policies<I>(self, policies: I) -> Self
    where
        I: IntoIterator<Item = TrustedTypesPolicy>,
    {
        self.trusted_types_tokens(policies.into_iter().map(TrustedTypesToken::from))
    }

    pub fn trusted_types_none(mut self) -> Self {
        self.set_directive(CspDirective::TrustedTypes.as_str(), "'none'");
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

        self
    }

    fn set_directive_sources<I, S>(&mut self, directive: CspDirective, sources: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<CspSource>,
    {
        let value = format_sources(sources);
        self.set_directive(directive.as_str(), &value);
    }

    fn set_flag_directive(&mut self, directive: CspDirective) {
        self.set_directive(directive.as_str(), "");
    }

    pub fn script_src_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_script_src_token(&token);
        self
    }

    pub fn script_src_with_nonce(self, nonce: CspNonce) -> Self {
        self.script_src_nonce(nonce.into_inner())
    }

    pub fn script_src_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_script_src_token(&token);
        self
    }

    pub fn enable_strict_dynamic(mut self) -> Self {
        self.add_script_src_token("'strict-dynamic'");
        self
    }

    pub fn require_trusted_types_for_scripts(mut self) -> Self {
        self.set_directive(CspDirective::RequireTrustedTypesFor.as_str(), "'script'");
        self
    }

    pub fn generate_nonce() -> String {
        Self::generate_nonce_with_size(32)
    }

    pub fn generate_nonce_with_size(byte_len: usize) -> String {
        if byte_len == 0 {
            return String::new();
        }

        let mut buffer = vec![0u8; byte_len];
        OsRng.fill_bytes(&mut buffer);
        general_purpose::STANDARD.encode(buffer)
    }

    pub fn script_src_elem_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_directive_token(CspDirective::ScriptSrcElem.as_str(), &token);
        self
    }

    pub fn script_src_elem_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_directive_token(CspDirective::ScriptSrcElem.as_str(), &token);
        self
    }

    pub fn script_src_attr_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_directive_token(CspDirective::ScriptSrcAttr.as_str(), &token);
        self
    }

    pub fn script_src_attr_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_directive_token(CspDirective::ScriptSrcAttr.as_str(), &token);
        self
    }

    pub fn style_src_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_directive_token(CspDirective::StyleSrc.as_str(), &token);
        self
    }

    pub fn style_src_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_directive_token(CspDirective::StyleSrc.as_str(), &token);
        self
    }

    pub fn style_src_elem_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_directive_token(CspDirective::StyleSrcElem.as_str(), &token);
        self
    }

    pub fn style_src_elem_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_directive_token(CspDirective::StyleSrcElem.as_str(), &token);
        self
    }

    pub fn style_src_attr_nonce<S>(mut self, nonce: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!("'nonce-{}'", sanitize_token_input(nonce.into()));
        self.add_directive_token(CspDirective::StyleSrcAttr.as_str(), &token);
        self
    }

    pub fn style_src_attr_hash<S>(mut self, algorithm: CspHashAlgorithm, hash: S) -> Self
    where
        S: Into<String>,
    {
        let token = format!(
            "'{}{}'",
            algorithm.prefix(),
            sanitize_token_input(hash.into())
        );
        self.add_directive_token(CspDirective::StyleSrcAttr.as_str(), &token);
        self
    }

    pub(crate) fn is_valid_directive_name(name: &str) -> bool {
        CspDirective::ALL
            .iter()
            .any(|directive| directive.as_str() == name)
    }

    pub fn header_value(&self) -> String {
        self.directives
            .iter()
            .map(|(name, value)| {
                if value.is_empty() {
                    name.clone()
                } else {
                    format!("{} {}", name, value)
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn add_script_src_token(&mut self, token: &str) {
        self.add_directive_token(CspDirective::ScriptSrc.as_str(), token);
    }

    fn add_directive_token(&mut self, directive: &str, token: &str) {
        if let Some((_, value)) = self
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
        {
            if !contains_token(value, token) {
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(token);
            }
        } else {
            self.directives
                .push((directive.to_string(), token.to_string()));
        }
    }

    fn set_directive(&mut self, directive: &str, value: &str) {
        if let Some((_, existing)) = self
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
        {
            *existing = value.to_string();
        } else {
            self.directives
                .push((directive.to_string(), value.to_string()));
        }
    }
}

impl FeatureOptions for CspOptions {
    type Error = CspOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_with_warnings().map(|_| ())
    }
}

fn format_sources<I, S>(sources: I) -> String
where
    I: IntoIterator<Item = S>,
    S: Into<CspSource>,
{
    let mut parts: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for source in sources.into_iter() {
        let rendered = source.into().to_string();
        if rendered.is_empty() {
            continue;
        }

        if seen.insert(rendered.clone()) {
            parts.push(rendered);
        }
    }

    parts.join(" ")
}

fn sanitize_token_input(input: String) -> String {
    input.trim().trim_matches('\'').to_string()
}

fn contains_token(value: &str, token: &str) -> bool {
    value.split_whitespace().any(|existing| existing == token)
}

type TokenValidationCache = HashMap<String, Result<(), CspOptionsError>>;

impl CspOptions {
    pub fn validate_with_warnings(&self) -> Result<Vec<CspOptionsWarning>, CspOptionsError> {
        if self.directives.is_empty() {
            return Err(CspOptionsError::MissingDirectives);
        }

        let mut token_cache = TokenValidationCache::new();

        for (name, value) in &self.directives {
            if !Self::is_valid_directive_name(name) {
                return Err(CspOptionsError::InvalidDirectiveName);
            }

            Self::validate_directive_value(name, value, &mut token_cache)?;
        }

        let script_src = self.directive_value(CspDirective::ScriptSrc.as_str());
        let script_src_elem = self.directive_value(CspDirective::ScriptSrcElem.as_str());
        Self::validate_strict_dynamic_rules(script_src, script_src_elem)?;
        Self::validate_strict_dynamic_host_sources(script_src, script_src_elem)?;

        let mut warnings = Vec::new();
        Self::validate_worker_fallback(self, &mut warnings)?;
        self.emit_mixed_content_dependency_warnings(&mut warnings);
        self.emit_risky_scheme_warnings(&mut warnings);

        Ok(warnings)
    }

    fn directive_value(&self, name: &str) -> Option<&str> {
        self.directives
            .iter()
            .find(|(directive, _)| directive == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.trim().is_empty())
    }

    fn has_directive(&self, name: &str) -> bool {
        self.directives
            .iter()
            .any(|(directive, _)| directive == name)
    }

    fn has_invalid_header_text(value: &str) -> bool {
        value.contains(['\r', '\n'])
    }

    fn validate_directive_value(
        name: &str,
        value: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            if Self::allows_empty_value(name) {
                return Ok(());
            }

            return Err(CspOptionsError::InvalidDirectiveValue);
        }

        if Self::has_invalid_header_text(value) {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        if name == CspDirective::Sandbox.as_str() {
            return Self::validate_sandbox_tokens(trimmed);
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();

        if Self::directive_expects_sources(name) && Self::contains_conflicting_none(&tokens) {
            return Err(CspOptionsError::ConflictingNoneToken);
        }

        for &token in &tokens {
            Self::validate_token(name, token)?;

            if Self::directive_expects_sources(name) && !token.starts_with('\'') {
                Self::validate_source_expression_cached(token, cache)?;
                Self::enforce_scheme_restrictions(name, token)?;
            }
        }

        Self::validate_unsafe_hashes_semantics(name, &tokens)?;

        Ok(())
    }

    fn validate_token(directive: &str, token: &str) -> Result<(), CspOptionsError> {
        if token.is_empty() {
            return Err(CspOptionsError::InvalidDirectiveValue);
        }

        if let Some(rest) = token.strip_prefix("'nonce-") {
            if !Self::directive_supports_nonces(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
            return Self::validate_nonce(rest);
        }

        if let Some(rest) = token.strip_prefix("'sha256-") {
            if !Self::directive_supports_hashes(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
            return Self::validate_hash(rest, 44);
        }

        if let Some(rest) = token.strip_prefix("'sha384-") {
            if !Self::directive_supports_hashes(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
            return Self::validate_hash(rest, 64);
        }

        if let Some(rest) = token.strip_prefix("'sha512-") {
            if !Self::directive_supports_hashes(directive) {
                return Err(CspOptionsError::TokenNotAllowedForDirective(
                    token.to_string(),
                    directive.to_string(),
                ));
            }
            return Self::validate_hash(rest, 88);
        }

        if token.starts_with('"') || token.ends_with('"') {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        if token.starts_with('\'') && !token.ends_with('\'') {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        if token.chars().any(|ch| ch.is_control()) {
            return Err(CspOptionsError::InvalidDirectiveToken);
        }

        match token {
            "'unsafe-inline'" => {
                if !Self::directive_supports_unsafe_inline(directive) {
                    return Err(CspOptionsError::TokenNotAllowedForDirective(
                        token.to_string(),
                        directive.to_string(),
                    ));
                }
            }
            "'unsafe-eval'" => {
                if !Self::directive_supports_unsafe_eval(directive) {
                    return Err(CspOptionsError::TokenNotAllowedForDirective(
                        token.to_string(),
                        directive.to_string(),
                    ));
                }
            }
            "'unsafe-hashes'" => {
                if !Self::directive_supports_unsafe_hashes(directive) {
                    return Err(CspOptionsError::TokenNotAllowedForDirective(
                        token.to_string(),
                        directive.to_string(),
                    ));
                }
            }
            "'wasm-unsafe-eval'" => {
                if !Self::directive_supports_wasm_unsafe_eval(directive) {
                    return Err(CspOptionsError::TokenNotAllowedForDirective(
                        token.to_string(),
                        directive.to_string(),
                    ));
                }
            }
            "'report-sample'" => {
                if !Self::directive_supports_report_sample(directive) {
                    return Err(CspOptionsError::TokenNotAllowedForDirective(
                        token.to_string(),
                        directive.to_string(),
                    ));
                }
            }
            _ => {}
        }

        if token == "'strict-dynamic'" && !Self::directive_supports_strict_dynamic(directive) {
            return Err(CspOptionsError::TokenNotAllowedForDirective(
                token.to_string(),
                directive.to_string(),
            ));
        }

        Ok(())
    }

    fn validate_nonce(rest: &str) -> Result<(), CspOptionsError> {
        let encoded = rest
            .strip_suffix('\'')
            .ok_or(CspOptionsError::InvalidNonce)?;

        if encoded.len() < 22 {
            return Err(CspOptionsError::InvalidNonce);
        }

        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
        {
            return Err(CspOptionsError::InvalidNonce);
        }

        Ok(())
    }

    fn validate_hash(rest: &str, expected_len: usize) -> Result<(), CspOptionsError> {
        let encoded = rest
            .strip_suffix('\'')
            .ok_or(CspOptionsError::InvalidHash)?;

        if encoded.len() != expected_len {
            return Err(CspOptionsError::InvalidHash);
        }

        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
        {
            return Err(CspOptionsError::InvalidHash);
        }

        Ok(())
    }

    fn directive_supports_nonces(name: &str) -> bool {
        matches!(
            name,
            "script-src"
                | "script-src-elem"
                | "script-src-attr"
                | "style-src"
                | "style-src-elem"
                | "style-src-attr"
        )
    }

    fn directive_supports_hashes(name: &str) -> bool {
        Self::directive_supports_nonces(name)
    }

    fn directive_supports_strict_dynamic(name: &str) -> bool {
        matches!(name, "script-src" | "script-src-elem")
    }

    fn directive_supports_unsafe_inline(name: &str) -> bool {
        Self::directive_is_script_family(name) || Self::directive_is_style_family(name)
    }

    fn directive_supports_unsafe_eval(name: &str) -> bool {
        matches!(name, "script-src" | "script-src-elem")
    }

    fn directive_supports_unsafe_hashes(name: &str) -> bool {
        matches!(name, "script-src" | "style-src")
    }

    fn directive_supports_wasm_unsafe_eval(name: &str) -> bool {
        matches!(name, "script-src" | "script-src-elem")
    }

    fn directive_supports_report_sample(name: &str) -> bool {
        Self::directive_is_script_family(name) || Self::directive_is_style_family(name)
    }

    fn directive_is_script_family(name: &str) -> bool {
        matches!(name, "script-src" | "script-src-elem" | "script-src-attr")
    }

    fn directive_is_style_family(name: &str) -> bool {
        matches!(name, "style-src" | "style-src-elem" | "style-src-attr")
    }

    fn directive_expects_sources(name: &str) -> bool {
        matches!(
            name,
            "default-src"
                | "script-src"
                | "script-src-elem"
                | "script-src-attr"
                | "style-src"
                | "style-src-elem"
                | "style-src-attr"
                | "img-src"
                | "connect-src"
                | "font-src"
                | "frame-src"
                | "worker-src"
                | "media-src"
                | "manifest-src"
                | "object-src"
                | "navigate-to"
                | "base-uri"
                | "form-action"
                | "frame-ancestors"
        )
    }

    fn allows_empty_value(name: &str) -> bool {
        matches!(
            name,
            "upgrade-insecure-requests" | "block-all-mixed-content" | "sandbox"
        )
    }

    fn contains_conflicting_none(tokens: &[&str]) -> bool {
        tokens.contains(&"'none'") && tokens.len() > 1
    }

    fn validate_sandbox_tokens(value: &str) -> Result<(), CspOptionsError> {
        for token in value.split_whitespace() {
            if SandboxToken::from_str(token).is_none() {
                return Err(CspOptionsError::InvalidSandboxToken(token.to_string()));
            }
        }

        Ok(())
    }

    fn validate_strict_dynamic_rules(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> Result<(), CspOptionsError> {
        let mut has_strict_dynamic = false;
        let mut has_nonce_or_hash = false;
        let mut has_conflicts = false;

        for directive in [script_src, script_src_elem].into_iter().flatten() {
            for token in directive.split_whitespace() {
                match token {
                    "'strict-dynamic'" => has_strict_dynamic = true,
                    "'unsafe-inline'" | "'unsafe-eval'" | "'unsafe-hashes'" => has_conflicts = true,
                    _ => {
                        if token.starts_with("'nonce-")
                            || token.starts_with("'sha256-")
                            || token.starts_with("'sha384-")
                            || token.starts_with("'sha512-")
                        {
                            has_nonce_or_hash = true;
                        }
                    }
                }
            }
        }

        if has_strict_dynamic {
            if !has_nonce_or_hash {
                return Err(CspOptionsError::StrictDynamicRequiresNonceOrHash);
            }

            if has_conflicts {
                return Err(CspOptionsError::StrictDynamicConflicts);
            }
        }

        Ok(())
    }

    fn strict_dynamic_has_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> bool {
        let mut has_strict_dynamic = false;
        let mut has_host_like_tokens = false;

        for directive in [script_src, script_src_elem].into_iter().flatten() {
            for token in directive.split_whitespace() {
                match token {
                    "'strict-dynamic'" => has_strict_dynamic = true,
                    _ if token.starts_with("'nonce-") || token.starts_with("'sha256-") => {}
                    _ if token.starts_with("'sha384-") || token.starts_with("'sha512-") => {}
                    "'unsafe-inline'" | "'unsafe-eval'" | "'unsafe-hashes'"
                    | "'wasm-unsafe-eval'" => {}
                    "'report-sample'" => {}
                    "'self'" => has_host_like_tokens = true,
                    _ if token.starts_with('\'') => {}
                    _ => has_host_like_tokens = true,
                }
            }
        }

        has_strict_dynamic && has_host_like_tokens
    }

    fn validate_strict_dynamic_host_sources(
        script_src: Option<&str>,
        script_src_elem: Option<&str>,
    ) -> Result<(), CspOptionsError> {
        if Self::strict_dynamic_has_host_sources(script_src, script_src_elem) {
            Err(CspOptionsError::StrictDynamicHostSourceConflict)
        } else {
            Ok(())
        }
    }

    fn enforce_scheme_restrictions(directive: &str, token: &str) -> Result<(), CspOptionsError> {
        if let Some(scheme) = token.strip_suffix(':') {
            if scheme.contains('/') {
                return Ok(());
            }

            let lowered = scheme.to_ascii_lowercase();
            const DISALLOWED_SCHEMES: [&str; 2] = ["javascript", "vbscript"];

            if DISALLOWED_SCHEMES.contains(&lowered.as_str()) {
                return Err(CspOptionsError::DisallowedScheme(
                    directive.to_string(),
                    lowered,
                ));
            }
        }

        Ok(())
    }

    fn validate_unsafe_hashes_semantics(
        directive: &str,
        tokens: &[&str],
    ) -> Result<(), CspOptionsError> {
        if !tokens.contains(&"'unsafe-hashes'") {
            return Ok(());
        }

        let has_hash_token = tokens.iter().any(|token| {
            token.starts_with("'sha256-")
                || token.starts_with("'sha384-")
                || token.starts_with("'sha512-")
        });

        if has_hash_token {
            Ok(())
        } else {
            Err(CspOptionsError::UnsafeHashesRequireHashes(
                directive.to_string(),
            ))
        }
    }

    fn validate_source_expression_cached(
        token: &str,
        cache: &mut TokenValidationCache,
    ) -> Result<(), CspOptionsError> {
        if let Some(result) = cache.get(token) {
            return result.clone();
        }

        let result = Self::validate_source_expression(token);
        cache.insert(token.to_string(), result.clone());
        result
    }

    fn validate_source_expression(token: &str) -> Result<(), CspOptionsError> {
        if token == "*" {
            return Ok(());
        }

        if token
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
        }

        if token.ends_with(':') && !token.contains('/') {
            return Self::validate_scheme_source(token);
        }

        if token.starts_with('/') {
            return Self::validate_path_source(token);
        }

        if token.starts_with("*.") {
            return Self::validate_wildcard_host(token);
        }

        Self::validate_host_source(token)
    }

    fn validate_scheme_source(token: &str) -> Result<(), CspOptionsError> {
        let scheme = token.trim_end_matches(':');

        let mut chars = scheme.chars();

        match chars.next() {
            Some(first) if first.is_ascii_alphabetic() => {}
            _ => return Err(CspOptionsError::InvalidSourceExpression(token.to_string())),
        }

        if chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
            Ok(())
        } else {
            Err(CspOptionsError::InvalidSourceExpression(token.to_string()))
        }
    }

    fn validate_host_source(token: &str) -> Result<(), CspOptionsError> {
        Self::validate_host_like_source(token, token)
    }

    fn validate_host_like_source(value: &str, original: &str) -> Result<(), CspOptionsError> {
        let base_candidate = if value.contains("//") {
            value.to_string()
        } else {
            format!("https://{}", value)
        };

        let candidate = Self::normalize_port_wildcard(base_candidate, original)?;

        let parsed = Url::parse(&candidate)
            .map_err(|_| CspOptionsError::InvalidSourceExpression(original.to_string()))?;

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ));
        }

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ));
        }

        if let Some(host) = parsed.host_str() {
            if host.is_empty() {
                return Err(CspOptionsError::InvalidSourceExpression(
                    original.to_string(),
                ));
            }
        } else {
            return Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ));
        }

        let path = parsed.path();
        if !path.is_empty()
            && path != "/"
            && (!path.starts_with('/') || path.chars().any(|ch| ch.is_control()))
        {
            return Err(CspOptionsError::InvalidSourceExpression(
                original.to_string(),
            ));
        }

        Ok(())
    }

    fn normalize_port_wildcard(
        candidate: String,
        original: &str,
    ) -> Result<String, CspOptionsError> {
        if let Some(index) = candidate.find(":*") {
            let after = &candidate[index + 2..];
            if after.is_empty() || after.starts_with('/') {
                Err(CspOptionsError::PortWildcardUnsupported(
                    original.to_string(),
                ))
            } else {
                Err(CspOptionsError::InvalidSourceExpression(
                    original.to_string(),
                ))
            }
        } else {
            Ok(candidate)
        }
    }

    fn validate_wildcard_host(token: &str) -> Result<(), CspOptionsError> {
        let rest = &token[2..];
        if rest.is_empty() {
            return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
        }

        if rest.contains('*') {
            return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
        }

        Self::validate_host_like_source(rest, token)
    }

    fn validate_path_source(token: &str) -> Result<(), CspOptionsError> {
        if token
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(CspOptionsError::InvalidSourceExpression(token.to_string()));
        }

        if token.starts_with('/') {
            Ok(())
        } else {
            Err(CspOptionsError::InvalidSourceExpression(token.to_string()))
        }
    }

    fn is_permissive_default_source(value: &str) -> bool {
        value.split_whitespace().any(|token| token == "*")
    }

    fn validate_worker_fallback(
        options: &CspOptions,
        warnings: &mut Vec<CspOptionsWarning>,
    ) -> Result<(), CspOptionsError> {
        if options
            .directive_value(CspDirective::WorkerSrc.as_str())
            .is_some()
        {
            return Ok(());
        }

        let has_script = options
            .directive_value(CspDirective::ScriptSrc.as_str())
            .is_some();
        if has_script {
            return Ok(());
        }

        if let Some(default_value) = options.directive_value(CspDirective::DefaultSrc.as_str()) {
            if Self::is_permissive_default_source(default_value) {
                warnings.push(CspOptionsWarning::warning(
                    CspOptionsWarningKind::WeakWorkerSrcFallback,
                ));
            }
            return Ok(());
        }

        warnings.push(CspOptionsWarning::critical(
            CspOptionsWarningKind::MissingWorkerSrcFallback,
        ));
        Ok(())
    }

    fn emit_mixed_content_dependency_warnings(&self, warnings: &mut Vec<CspOptionsWarning>) {
        let has_upgrade = self.has_directive(CspDirective::UpgradeInsecureRequests.as_str());
        let has_block = self.has_directive(CspDirective::BlockAllMixedContent.as_str());

        if has_upgrade && !has_block {
            warnings.push(CspOptionsWarning::warning(
                CspOptionsWarningKind::UpgradeInsecureRequestsWithoutBlockAllMixedContent,
            ));
        }

        if has_block && !has_upgrade {
            warnings.push(CspOptionsWarning::warning(
                CspOptionsWarningKind::BlockAllMixedContentWithoutUpgradeInsecureRequests,
            ));
        }
    }

    fn emit_risky_scheme_warnings(&self, warnings: &mut Vec<CspOptionsWarning>) {
        const RISKY_SCHEMES: [(&str, CspWarningSeverity); 3] = [
            ("data:", CspWarningSeverity::Critical),
            ("blob:", CspWarningSeverity::Warning),
            ("filesystem:", CspWarningSeverity::Critical),
        ];

        struct SchemeAggregation {
            schemes: HashSet<String>,
            severity: CspWarningSeverity,
        }

        let mut aggregated: HashMap<String, SchemeAggregation> = HashMap::new();

        for (directive, value) in &self.directives {
            if !Self::directive_expects_sources(directive) {
                continue;
            }

            for token in value.split_whitespace() {
                let lowered = token.to_ascii_lowercase();

                for &(scheme, severity) in RISKY_SCHEMES.iter() {
                    if lowered.starts_with(scheme) {
                        let entry = aggregated.entry(directive.clone()).or_insert_with(|| {
                            SchemeAggregation {
                                schemes: HashSet::new(),
                                severity: CspWarningSeverity::Info,
                            }
                        });
                        entry.severity = entry.severity.max(severity);
                        entry
                            .schemes
                            .insert(scheme.trim_end_matches(':').to_string());
                    }
                }
            }
        }

        let mut aggregated_entries: Vec<_> = aggregated.into_iter().collect();
        aggregated_entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (directive, entry) in aggregated_entries {
            let mut schemes: Vec<String> = entry.schemes.into_iter().collect();
            schemes.sort();

            let kind = CspOptionsWarningKind::RiskySchemes { directive, schemes };
            let warning = match entry.severity {
                CspWarningSeverity::Critical => CspOptionsWarning::critical(kind),
                CspWarningSeverity::Warning => CspOptionsWarning::warning(kind),
                CspWarningSeverity::Info => CspOptionsWarning::info(kind),
            };

            warnings.push(warning);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CspOptionsError {
    #[error("missing directives")]
    MissingDirectives,
    #[error("invalid directive name")]
    InvalidDirectiveName,
    #[error("invalid directive value")]
    InvalidDirectiveValue,
    #[error("invalid directive token")]
    InvalidDirectiveToken,
    #[error("invalid nonce source expression")]
    InvalidNonce,
    #[error("invalid hash source expression")]
    InvalidHash,
    #[error("'strict-dynamic' requires at least one nonce or hash source")]
    StrictDynamicRequiresNonceOrHash,
    #[error("'strict-dynamic' cannot be combined with unsafe-inline/unsafe-eval/unsafe-hashes")]
    StrictDynamicConflicts,
    #[error("'none' token cannot be combined with other sources")]
    ConflictingNoneToken,
    #[error("sandbox directive contains invalid token `{0}`")]
    InvalidSandboxToken(String),
    #[error("invalid source expression `{0}`")]
    InvalidSourceExpression(String),
    #[error("token `{0}` is not allowed in directive `{1}`")]
    TokenNotAllowedForDirective(String, String),
    #[error("'unsafe-hashes' in `{0}` requires at least one hash source expression")]
    UnsafeHashesRequireHashes(String),
    #[error("scheme `{1}` is not permitted in directive `{0}`")]
    DisallowedScheme(String, String),
    #[error("source expression `{0}` cannot use a wildcard port")]
    PortWildcardUnsupported(String),
    #[error("'strict-dynamic' cannot be combined with host or scheme sources")]
    StrictDynamicHostSourceConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspWarningSeverity {
    Info,
    Warning,
    Critical,
}

impl CspWarningSeverity {
    fn max(self, other: Self) -> Self {
        use CspWarningSeverity::*;

        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (Warning, _) | (_, Warning) => Warning,
            _ => Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspOptionsWarningKind {
    MissingWorkerSrcFallback,
    WeakWorkerSrcFallback,
    UpgradeInsecureRequestsWithoutBlockAllMixedContent,
    BlockAllMixedContentWithoutUpgradeInsecureRequests,
    RiskySchemes {
        directive: String,
        schemes: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspOptionsWarning {
    pub severity: CspWarningSeverity,
    pub kind: CspOptionsWarningKind,
}

impl CspOptionsWarning {
    pub(crate) fn info(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Info,
            kind,
        }
    }

    pub(crate) fn warning(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Warning,
            kind,
        }
    }

    pub(crate) fn critical(kind: CspOptionsWarningKind) -> Self {
        Self {
            severity: CspWarningSeverity::Critical,
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CspNonceManagerError {
    #[error("nonce length must be greater than zero")]
    InvalidLength,
}
