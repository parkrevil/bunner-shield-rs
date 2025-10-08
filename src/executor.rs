use crate::normalized_headers::NormalizedHeaders;

pub trait Executor {
    fn validate_options(&self) -> Result<(), String>;
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String>;
}
