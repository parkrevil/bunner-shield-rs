use crate::executor::FeatureOptions;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchMetadataOptions {
    pub(crate) allow_navigation_requests: bool,
    pub(crate) require_user_activation_for_navigation: bool,
    pub(crate) allow_legacy_clients: bool,
    pub(crate) navigation_destinations: Vec<FetchDestination>,
    pub(crate) cross_site_allowances: Vec<FetchMetadataRule>,
}

impl FetchMetadataOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_navigation_requests(mut self, allow: bool) -> Self {
        self.allow_navigation_requests = allow;
        self
    }

    pub fn require_user_activation_for_navigation(mut self, require: bool) -> Self {
        self.require_user_activation_for_navigation = require;
        self
    }

    pub fn navigation_destinations(
        mut self,
        destinations: impl IntoIterator<Item = FetchDestination>,
    ) -> Self {
        self.navigation_destinations.clear();
        for destination in destinations {
            self.push_navigation_destination(destination);
        }
        self
    }

    pub fn add_navigation_destination(mut self, destination: FetchDestination) -> Self {
        self.push_navigation_destination(destination);
        self
    }

    fn push_navigation_destination(&mut self, destination: FetchDestination) {
        if !self.navigation_destinations.contains(&destination) {
            self.navigation_destinations.push(destination);
        }
    }

    pub fn allow_legacy_clients(mut self, allow: bool) -> Self {
        self.allow_legacy_clients = allow;
        self
    }

    pub fn allow_cross_site_rule(mut self, rule: FetchMetadataRule) -> Self {
        if !self.cross_site_allowances.contains(&rule) {
            self.cross_site_allowances.push(rule);
        }
        self
    }

    pub fn allow_cross_site_rules(
        mut self,
        rules: impl IntoIterator<Item = FetchMetadataRule>,
    ) -> Self {
        for rule in rules {
            self = self.allow_cross_site_rule(rule);
        }
        self
    }
}

impl Default for FetchMetadataOptions {
    fn default() -> Self {
        Self {
            allow_navigation_requests: true,
            require_user_activation_for_navigation: true,
            allow_legacy_clients: true,
            navigation_destinations: vec![
                FetchDestination::Document,
                FetchDestination::NestedDocument,
            ],
            cross_site_allowances: Vec::new(),
        }
    }
}

impl FeatureOptions for FetchMetadataOptions {
    type Error = FetchMetadataOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.allow_navigation_requests && self.navigation_destinations.is_empty() {
            return Err(FetchMetadataOptionsError::EmptyNavigationDestinations);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchMetadataRule {
    mode: Option<FetchMode>,
    destination: Option<FetchDestination>,
}

impl FetchMetadataRule {
    pub fn new() -> Self {
        Self {
            mode: None,
            destination: None,
        }
    }

    pub fn mode(mut self, mode: FetchMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn destination(mut self, destination: FetchDestination) -> Self {
        self.destination = Some(destination);
        self
    }

    pub(crate) fn matches(
        &self,
        mode: Option<&FetchMode>,
        destination: Option<&FetchDestination>,
    ) -> bool {
        if let Some(expected_mode) = &self.mode {
            match mode {
                Some(actual_mode) if actual_mode == expected_mode => {}
                _ => return false,
            }
        }

        if let Some(expected_destination) = &self.destination {
            match destination {
                Some(actual_destination) if actual_destination == expected_destination => {}
                _ => return false,
            }
        }

        true
    }
}

impl Default for FetchMetadataRule {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchSite {
    None,
    SameOrigin,
    SameSite,
    CrossSite,
    Other(String),
}

impl FetchSite {
    pub fn as_str(&self) -> &str {
        match self {
            FetchSite::None => "none",
            FetchSite::SameOrigin => "same-origin",
            FetchSite::SameSite => "same-site",
            FetchSite::CrossSite => "cross-site",
            FetchSite::Other(value) => value.as_str(),
        }
    }
}

impl FromStr for FetchSite {
    type Err = FetchMetadataParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "none" => Ok(FetchSite::None),
            "same-origin" => Ok(FetchSite::SameOrigin),
            "same-site" => Ok(FetchSite::SameSite),
            "cross-site" => Ok(FetchSite::CrossSite),
            "" => Err(FetchMetadataParseError::InvalidSite(value.to_string())),
            other => Ok(FetchSite::Other(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchMode {
    Cors,
    Navigate,
    NoCors,
    SameOrigin,
    Websocket,
    Other(String),
}

impl FetchMode {
    pub fn as_str(&self) -> &str {
        match self {
            FetchMode::Cors => "cors",
            FetchMode::Navigate => "navigate",
            FetchMode::NoCors => "no-cors",
            FetchMode::SameOrigin => "same-origin",
            FetchMode::Websocket => "websocket",
            FetchMode::Other(value) => value.as_str(),
        }
    }

    pub fn other(value: impl Into<String>) -> Self {
        Self::Other(value.into())
    }
}

impl FromStr for FetchMode {
    type Err = FetchMetadataParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "cors" => Ok(FetchMode::Cors),
            "navigate" => Ok(FetchMode::Navigate),
            "no-cors" => Ok(FetchMode::NoCors),
            "same-origin" => Ok(FetchMode::SameOrigin),
            "websocket" => Ok(FetchMode::Websocket),
            "" => Err(FetchMetadataParseError::InvalidMode(value.to_string())),
            other => Ok(FetchMode::Other(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchDestination {
    Audio,
    AudioWorklet,
    Document,
    Embed,
    Empty,
    Font,
    Frame,
    Iframe,
    Image,
    Manifest,
    Object,
    PaintWorklet,
    Report,
    Script,
    ServiceWorker,
    SharedWorker,
    Style,
    Track,
    Video,
    Worker,
    WebIdentity,
    NestedDocument,
    Other(String),
}

impl FetchDestination {
    pub fn as_str(&self) -> &str {
        match self {
            FetchDestination::Audio => "audio",
            FetchDestination::AudioWorklet => "audioworklet",
            FetchDestination::Document => "document",
            FetchDestination::Embed => "embed",
            FetchDestination::Empty => "empty",
            FetchDestination::Font => "font",
            FetchDestination::Frame => "frame",
            FetchDestination::Iframe => "iframe",
            FetchDestination::Image => "image",
            FetchDestination::Manifest => "manifest",
            FetchDestination::Object => "object",
            FetchDestination::PaintWorklet => "paintworklet",
            FetchDestination::Report => "report",
            FetchDestination::Script => "script",
            FetchDestination::ServiceWorker => "serviceworker",
            FetchDestination::SharedWorker => "sharedworker",
            FetchDestination::Style => "style",
            FetchDestination::Track => "track",
            FetchDestination::Video => "video",
            FetchDestination::Worker => "worker",
            FetchDestination::WebIdentity => "webidentity",
            FetchDestination::NestedDocument => "nested-document",
            FetchDestination::Other(value) => value.as_str(),
        }
    }

    pub fn other(value: impl Into<String>) -> Self {
        Self::Other(value.into())
    }
}

impl FromStr for FetchDestination {
    type Err = FetchMetadataParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "audio" => Ok(FetchDestination::Audio),
            "audioworklet" => Ok(FetchDestination::AudioWorklet),
            "document" => Ok(FetchDestination::Document),
            "embed" => Ok(FetchDestination::Embed),
            "empty" => Ok(FetchDestination::Empty),
            "font" => Ok(FetchDestination::Font),
            "frame" => Ok(FetchDestination::Frame),
            "iframe" => Ok(FetchDestination::Iframe),
            "image" => Ok(FetchDestination::Image),
            "manifest" => Ok(FetchDestination::Manifest),
            "object" => Ok(FetchDestination::Object),
            "paintworklet" => Ok(FetchDestination::PaintWorklet),
            "report" => Ok(FetchDestination::Report),
            "script" => Ok(FetchDestination::Script),
            "serviceworker" => Ok(FetchDestination::ServiceWorker),
            "sharedworker" => Ok(FetchDestination::SharedWorker),
            "style" => Ok(FetchDestination::Style),
            "track" => Ok(FetchDestination::Track),
            "video" => Ok(FetchDestination::Video),
            "worker" => Ok(FetchDestination::Worker),
            "webidentity" => Ok(FetchDestination::WebIdentity),
            "nested-document" => Ok(FetchDestination::NestedDocument),
            "" => Err(FetchMetadataParseError::InvalidDestination(
                value.to_string(),
            )),
            other => Ok(FetchDestination::Other(other.to_string())),
        }
    }
}

impl fmt::Display for FetchDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for FetchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for FetchSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FetchMetadataOptionsError {
    #[error(
        "fetch metadata navigation destinations must not be empty when navigation requests are allowed"
    )]
    EmptyNavigationDestinations,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FetchMetadataParseError {
    #[error("invalid Sec-Fetch-Site value `{0}`")]
    InvalidSite(String),
    #[error("invalid Sec-Fetch-Mode value `{0}`")]
    InvalidMode(String),
    #[error("invalid Sec-Fetch-Dest value `{0}`")]
    InvalidDestination(String),
}

#[cfg(test)]
#[path = "options_test.rs"]
mod options_test;
