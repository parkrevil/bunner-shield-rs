use super::{CachedHeader, DynFeatureExecutor, ExecutorError, FeatureExecutor, FeatureOptions};
use crate::normalized_headers::NormalizedHeaders;
use crate::tests_common as common;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct ToggleOptions {
    valid: bool,
}

#[derive(Debug, Clone)]
struct ToggleOptionsError(&'static str);

impl std::fmt::Display for ToggleOptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ToggleOptionsError {}

impl FeatureOptions for ToggleOptions {
    type Error = ToggleOptionsError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.valid {
            Ok(())
        } else {
            Err(ToggleOptionsError("invalid toggle"))
        }
    }
}

struct ToggleExecutor {
    options: ToggleOptions,
    observed: Arc<Mutex<Vec<String>>>,
}

impl ToggleExecutor {
    fn new(options: ToggleOptions, observed: Arc<Mutex<Vec<String>>>) -> Self {
        Self { options, observed }
    }
}

impl FeatureExecutor for ToggleExecutor {
    type Options = ToggleOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert_owned("x-test", "applied".to_string());
        self.observed
            .lock()
            .expect("lock")
            .push("applied".to_string());
        Ok(())
    }
}

mod validate_options {
    use super::*;

    #[test]
    fn given_valid_options_when_validate_then_returns_ok() {
        let executor = ToggleExecutor::new(ToggleOptions { valid: true }, Arc::default());

        let result = FeatureExecutor::validate_options(&executor);

        assert!(result.is_ok());
    }

    #[test]
    fn given_invalid_options_when_validate_then_wraps_error_in_box() {
        let executor = ToggleExecutor::new(ToggleOptions { valid: false }, Arc::default());

        let result = FeatureExecutor::validate_options(&executor);

        let message = result.expect_err("expected error").to_string();
        assert_eq!(message, "invalid toggle");
    }
}

mod dyn_feature_executor {
    use super::*;

    #[test]
    fn given_dyn_feature_executor_when_execute_then_delegates_to_implementation() {
        let observed = Arc::default();
        let executor: Box<dyn DynFeatureExecutor> = Box::new(ToggleExecutor::new(
            ToggleOptions { valid: true },
            Arc::clone(&observed),
        ));
        let mut headers = common::normalized_headers_from(&[]);

        executor.execute(&mut headers).expect("execute");

        let normalized = headers.into_result();
        assert_eq!(
            normalized.get("x-test").map(String::as_str),
            Some("applied")
        );

        let observed_values = observed.lock().expect("lock").clone();
        assert_eq!(observed_values, vec!["applied".to_string()]);
    }

    #[test]
    fn given_dyn_feature_executor_when_validate_options_then_delegates_to_validate() {
        let executor: Box<dyn DynFeatureExecutor> = Box::new(ToggleExecutor::new(
            ToggleOptions { valid: true },
            Arc::default(),
        ));

        let result = executor.validate_options();

        assert!(result.is_ok());
    }
}

mod cached_header {
    use super::*;

    #[test]
    fn given_cached_header_when_new_then_caches_options_and_value() {
        let header = CachedHeader::new(ToggleOptions { valid: true }, Cow::Borrowed("value"));

        assert!(header.options().valid);
        assert_eq!(header.cloned_header_value(), Cow::Borrowed("value"));
    }
}
