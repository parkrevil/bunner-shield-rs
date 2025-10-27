use super::options::{
    FetchDestination, FetchMetadataOptions, FetchMetadataParseError, FetchMode, FetchSite,
};
use crate::constants::header_keys::{
    SEC_FETCH_DEST, SEC_FETCH_MODE, SEC_FETCH_SITE, SEC_FETCH_USER,
};
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;
use std::str::FromStr;
use thiserror::Error;

pub struct FetchMetadata {
    options: FetchMetadataOptions,
}

impl FetchMetadata {
    pub fn new(options: FetchMetadataOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for FetchMetadata {
    type Options = FetchMetadataOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        let site_value = header_value(headers, SEC_FETCH_SITE);
        let site = match site_value {
            Some(raw) => parse_site(raw)?,
            None => {
                if self.options.allow_legacy_clients {
                    return Ok(());
                }
                return Err(Box::new(FetchMetadataError::MissingHeaders) as ExecutorError);
            }
        };

        match site {
            FetchSite::None | FetchSite::SameOrigin | FetchSite::SameSite => Ok(()),
            FetchSite::CrossSite => self.evaluate_cross_site(headers),
            FetchSite::Other(value) => Err(Box::new(FetchMetadataError::UnsupportedSite(value))),
        }
    }
}

impl FetchMetadata {
    fn evaluate_cross_site(&self, headers: &NormalizedHeaders) -> Result<(), ExecutorError> {
        let mode = parse_mode(header_value(headers, SEC_FETCH_MODE))?;
        let mode = match mode {
            Some(value) => value,
            None => {
                return Err(Box::new(FetchMetadataError::HeaderMissing {
                    header: SEC_FETCH_MODE,
                }) as ExecutorError);
            }
        };

        let destination = parse_destination(header_value(headers, SEC_FETCH_DEST))?;
        let destination_ref = Some(&destination);
        let user_header = header_value(headers, SEC_FETCH_USER);
        let user_initiated = user_header.map(|value| value.trim() == "?1");

        if self.navigation_allowed(&mode, destination_ref, user_initiated) {
            return Ok(());
        }

        if self
            .options
            .cross_site_allowances
            .iter()
            .any(|rule| rule.matches(Some(&mode), destination_ref))
        {
            return Ok(());
        }

        Err(Box::new(FetchMetadataError::CrossSiteBlocked {
            site: "cross-site".to_string(),
            mode: mode.as_str().to_string(),
            destination: destination.as_str().to_string(),
        }))
    }

    fn navigation_allowed(
        &self,
        mode: &FetchMode,
        destination: Option<&FetchDestination>,
        user_initiated: Option<bool>,
    ) -> bool {
        if !self.options.allow_navigation_requests {
            return false;
        }

        if mode != &FetchMode::Navigate {
            return false;
        }

        if self.options.require_user_activation_for_navigation && user_initiated != Some(true) {
            return false;
        }

        let Some(destination) = destination else {
            return false;
        };

        self.options
            .navigation_destinations
            .iter()
            .any(|allowed| allowed == destination)
    }
}

fn header_value<'a>(headers: &'a NormalizedHeaders, name: &str) -> Option<&'a str> {
    headers
        .get_all(name)
        .and_then(|values| values.first())
        .map(|value| value.as_ref())
}

fn parse_site(value: &str) -> Result<FetchSite, ExecutorError> {
    FetchSite::from_str(value).map_err(|error| match error {
        FetchMetadataParseError::InvalidSite(raw) => {
            Box::new(FetchMetadataError::InvalidHeaderValue {
                header: SEC_FETCH_SITE,
                value: raw,
            }) as ExecutorError
        }
        _ => unreachable!("mode and destination errors do not originate from site parsing"),
    })
}

fn parse_mode(value: Option<&str>) -> Result<Option<FetchMode>, ExecutorError> {
    match value {
        Some(raw) => FetchMode::from_str(raw)
            .map(Some)
            .map_err(|error| match error {
                FetchMetadataParseError::InvalidMode(raw) => {
                    Box::new(FetchMetadataError::InvalidHeaderValue {
                        header: SEC_FETCH_MODE,
                        value: raw,
                    }) as ExecutorError
                }
                _ => unreachable!("site/destination parse errors not expected"),
            }),
        None => Ok(None),
    }
}

fn parse_destination(value: Option<&str>) -> Result<FetchDestination, ExecutorError> {
    match value {
        Some(raw) => FetchDestination::from_str(raw).map_err(|error| match error {
            FetchMetadataParseError::InvalidDestination(raw) => {
                Box::new(FetchMetadataError::InvalidHeaderValue {
                    header: SEC_FETCH_DEST,
                    value: raw,
                }) as ExecutorError
            }
            _ => unreachable!("site/mode parse errors not expected"),
        }),
        None => Err(Box::new(FetchMetadataError::HeaderMissing {
            header: SEC_FETCH_DEST,
        }) as ExecutorError),
    }
}

#[derive(Debug, Error)]
pub enum FetchMetadataError {
    #[error("fetch metadata headers missing (legacy clients are not allowed)")]
    MissingHeaders,
    #[error("required fetch metadata header `{header}` missing")]
    HeaderMissing { header: &'static str },
    #[error("invalid value `{value}` for header `{header}`")]
    InvalidHeaderValue { header: &'static str, value: String },
    #[error("unsupported Sec-Fetch-Site value `{0}`")]
    UnsupportedSite(String),
    #[error("cross-site request blocked (site={site}, mode={mode}, destination={destination})")]
    CrossSiteBlocked {
        site: String,
        mode: String,
        destination: String,
    },
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
