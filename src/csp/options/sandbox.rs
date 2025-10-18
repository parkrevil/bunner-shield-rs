use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub fn as_str(self) -> &'static str {
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

    pub fn parse(token: &str) -> Option<Self> {
        token.parse().ok()
    }
}

impl FromStr for SandboxToken {
    type Err = SandboxTokenParseError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        match token {
            "allow-downloads" => Ok(SandboxToken::AllowDownloads),
            "allow-forms" => Ok(SandboxToken::AllowForms),
            "allow-modals" => Ok(SandboxToken::AllowModals),
            "allow-orientation-lock" => Ok(SandboxToken::AllowOrientationLock),
            "allow-pointer-lock" => Ok(SandboxToken::AllowPointerLock),
            "allow-popups" => Ok(SandboxToken::AllowPopups),
            "allow-popups-to-escape-sandbox" => Ok(SandboxToken::AllowPopupsToEscapeSandbox),
            "allow-presentation" => Ok(SandboxToken::AllowPresentation),
            "allow-same-origin" => Ok(SandboxToken::AllowSameOrigin),
            "allow-scripts" => Ok(SandboxToken::AllowScripts),
            "allow-storage-access-by-user-activation" => {
                Ok(SandboxToken::AllowStorageAccessByUserActivation)
            }
            "allow-top-navigation" => Ok(SandboxToken::AllowTopNavigation),
            "allow-top-navigation-by-user-activation" => {
                Ok(SandboxToken::AllowTopNavigationByUserActivation)
            }
            "allow-top-navigation-to-custom-protocols" => {
                Ok(SandboxToken::AllowTopNavigationToCustomProtocols)
            }
            "allow-downloads-without-user-activation" => {
                Ok(SandboxToken::AllowDownloadsWithoutUserActivation)
            }
            other => Err(SandboxTokenParseError::new(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxTokenParseError {
    token: String,
}

impl SandboxTokenParseError {
    fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
        }
    }
}

impl fmt::Display for SandboxTokenParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid sandbox token `{}`", self.token)
    }
}

impl std::error::Error for SandboxTokenParseError {}
