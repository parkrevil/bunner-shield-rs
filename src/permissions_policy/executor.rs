use super::PermissionsPolicyOptions;
use crate::constants::header_keys::PERMISSIONS_POLICY;
use crate::executor::{ExecutorError, FeatureExecutor};
use crate::normalized_headers::NormalizedHeaders;

pub struct PermissionsPolicy {
    options: PermissionsPolicyOptions,
}

impl PermissionsPolicy {
    pub fn new(options: PermissionsPolicyOptions) -> Self {
        Self { options }
    }
}

impl FeatureExecutor for PermissionsPolicy {
    type Options = PermissionsPolicyOptions;

    fn options(&self) -> &Self::Options {
        &self.options
    }

    fn execute(&self, headers: &mut NormalizedHeaders) -> Result<(), ExecutorError> {
        headers.insert(PERMISSIONS_POLICY, self.options.header_value());

        Ok(())
    }
}
