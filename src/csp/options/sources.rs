use std::borrow::Cow;
use std::fmt;

use super::nonce::CspNonce;
use super::types::CspHashAlgorithm;
use super::utils::sanitize_token_input;

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
        CspSource::Nonce(nonce.into_inner())
    }
}

#[cfg(test)]
#[path = "sources_test.rs"]
mod sources_test;
