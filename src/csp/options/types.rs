#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl CspHashAlgorithm {
    pub fn prefix(self) -> &'static str {
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
