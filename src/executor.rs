use crate::normalized_headers::NormalizedHeaders;
use std::borrow::Cow;
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

pub(crate) trait DynFeatureExecutor: Send + Sync {
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError>;
    fn validate_options(&self) -> Result<(), ExecutorError>;
}

impl<T> DynFeatureExecutor for T
where
    T: FeatureExecutor + Send + Sync,
{
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        FeatureExecutor::execute(self, headers)
    }

    fn validate_options(&self) -> Result<(), ExecutorError> {
        FeatureExecutor::validate_options(self)
    }
}

pub(crate) struct CachedHeader<O> {
    options: O,
    header_value: Cow<'static, str>,
}

impl<O> CachedHeader<O> {
    pub(crate) fn new(options: O, header_value: Cow<'static, str>) -> Self {
        Self {
            options,
            header_value,
        }
    }

    pub(crate) fn options(&self) -> &O {
        &self.options
    }

    pub(crate) fn cloned_header_value(&self) -> Cow<'static, str> {
        self.header_value.clone()
    }
}

/// Implements FeatureExecutor for types that expose a `cached: CachedHeader<Options>` field and
/// set a single header key to the cached value on execute.
///
/// Usage (inside the module defining the executor type):
/// impl_cached_header_executor!(TypeName, OptionsType, crate::constants::header_keys::SOME_KEY);
#[macro_export]
macro_rules! impl_cached_header_executor {
    ($struct:ty, $options_ty:ty, $header_key:path) => {
        impl $crate::executor::FeatureExecutor for $struct {
            type Options = $options_ty;

            fn options(&self) -> &Self::Options {
                self.cached.options()
            }

            fn execute(
                &self,
                headers: &mut $crate::normalized_headers::NormalizedHeaders,
            ) -> Result<(), $crate::executor::ExecutorError> {
                headers.insert($header_key, self.cached.cloned_header_value());
                Ok(())
            }
        }
    };
}

#[cfg(test)]
#[path = "executor_test.rs"]
mod executor_test;
