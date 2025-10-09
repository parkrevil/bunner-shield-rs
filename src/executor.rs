use crate::normalized_headers::NormalizedHeaders;
use std::error::Error as StdError;

pub type Executor = Box<dyn DynFeatureExecutor + 'static>;
pub type ExecutorError = Box<dyn StdError + Send + Sync>;

pub(crate) trait FeatureExecutor {
    type Options: FeatureOptions;

    fn options(&self) -> &Self::Options;
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError>;
    fn validate_options(&self) -> Result<(), ExecutorError> {
        self.options()
            .validate()
            .map_err(|err| Box::new(err) as ExecutorError)
    }
}

pub(crate) trait FeatureOptions {
    type Error: StdError + Send + Sync + 'static;

    fn validate(&self) -> Result<(), Self::Error>;
}

#[derive(Default)]
pub(crate) struct NoopOptions;

impl FeatureOptions for NoopOptions {
    type Error = std::convert::Infallible;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub(crate) trait DynFeatureExecutor {
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError>;
    fn validate_options(&self) -> Result<(), ExecutorError>;
}

impl<T> DynFeatureExecutor for T
where
    T: FeatureExecutor,
{
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        FeatureExecutor::execute(self, headers)
    }

    fn validate_options(&self) -> Result<(), ExecutorError> {
        FeatureExecutor::validate_options(self)
    }
}
