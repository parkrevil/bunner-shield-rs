use crate::normalized_headers::NormalizedHeaders;

pub trait FeatureExecutor {
    fn validate_options(&self) -> Result<(), String>;
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String>;
}

pub trait FeatureOptions {
    type Error;

    fn validate(&self) -> Result<(), Self::Error>;
}
