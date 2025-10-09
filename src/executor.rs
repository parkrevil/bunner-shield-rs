use crate::normalized_headers::NormalizedHeaders;

pub type ShieldExecutor = Box<dyn DynFeatureExecutor + 'static>;

pub(crate) trait FeatureExecutor {
    type Options: FeatureOptions;

    fn options(&self) -> &Self::Options;
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String>;
    fn validate_options(&self) -> Result<(), <Self::Options as FeatureOptions>::Error> {
        self.options().validate()
    }
}

pub(crate) trait FeatureOptions {
    type Error;

    fn validate(&self) -> Result<(), Self::Error>;
}

pub(crate) trait DynFeatureExecutor {
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String>;
    fn validate_options(&self) -> Result<(), String>;
}

impl<T> DynFeatureExecutor for T
where
    T: FeatureExecutor,
    <T::Options as FeatureOptions>::Error: std::fmt::Display,
{
    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), String> {
        FeatureExecutor::execute(self, headers)
    }

    fn validate_options(&self) -> Result<(), String> {
        FeatureExecutor::validate_options(self).map_err(|err| err.to_string())
    }
}
