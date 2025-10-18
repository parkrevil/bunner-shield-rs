use std::collections::HashMap;
use thiserror::Error;
use url::Url;

/// Represents a normalized origin (scheme, host, port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OriginTriple {
    scheme: String,
    host: String,
    port: u16,
}

impl OriginTriple {
    fn from_url(url: &Url) -> Option<Self> {
        let scheme = url.scheme().to_ascii_lowercase();
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        Some(Self { scheme, host, port })
    }
}

fn parse_origin_str(origin: &str) -> Result<OriginTriple, OriginCheckError> {
    // Origin header value is an origin (scheme://host[:port])
    // url::Url can parse it directly.
    let url = Url::parse(origin).map_err(|_| OriginCheckError::InvalidHeader("Origin"))?;
    OriginTriple::from_url(&url).ok_or(OriginCheckError::InvalidHeader("Origin"))
}

fn parse_referer_origin_str(referer: &str) -> Result<OriginTriple, OriginCheckError> {
    let url = Url::parse(referer).map_err(|_| OriginCheckError::InvalidHeader("Referer"))?;
    OriginTriple::from_url(&url).ok_or(OriginCheckError::InvalidHeader("Referer"))
}

fn get_header_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    let lname = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == lname)
        .map(|(_, v)| v.as_str())
}

/// Validates that the request's Origin (or Referer when fallback is enabled) matches one of the allowed origins.
///
/// Contract:
/// - Inputs: headers map, whether to use Referer when Origin is absent, and list of allowed origin strings (e.g., "https://example.com").
/// - Success: Ok(()) if origin matches.
/// - Failure: descriptive OriginCheckError explaining why validation failed.
pub(crate) fn validate_origin(
    headers: &HashMap<String, String>,
    use_referer: bool,
    allowed_origins: &[&str],
) -> Result<(), OriginCheckError> {
    if allowed_origins.is_empty() {
        return Err(OriginCheckError::NoAllowedOrigins);
    }

    let allow_list: Result<Vec<OriginTriple>, OriginCheckError> = allowed_origins
        .iter()
        .map(|s| parse_origin_str(s))
        .collect();
    let allow_list = allow_list?;

    if let Some(origin_val) = get_header_case_insensitive(headers, "Origin") {
        if origin_val.eq_ignore_ascii_case("null") || origin_val.trim().is_empty() {
            // Treat "null"/empty as missing origin
        } else {
            let req_origin = parse_origin_str(origin_val)?;
            let matched = allow_list.iter().any(|o| o == &req_origin);
            return if matched {
                Ok(())
            } else {
                Err(OriginCheckError::CrossOrigin)
            };
        }
    }

    if !use_referer {
        return Err(OriginCheckError::MissingOrigin);
    }

    if let Some(referer_val) = get_header_case_insensitive(headers, "Referer") {
        let req_origin = parse_referer_origin_str(referer_val)?;
        let matched = allow_list.iter().any(|o| o == &req_origin);
        if matched {
            Ok(())
        } else {
            Err(OriginCheckError::CrossOrigin)
        }
    } else {
        Err(OriginCheckError::MissingReferer)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OriginCheckError {
    #[error("no allowed origins provided")]
    NoAllowedOrigins,
    #[error("missing Origin header")]
    MissingOrigin,
    #[error("missing Referer header")]
    MissingReferer,
    #[error("invalid {0} header value")]
    InvalidHeader(&'static str),
    #[error("request is cross-origin")]
    CrossOrigin,
}

#[cfg(test)]
#[path = "origin_test.rs"]
mod origin_test;
