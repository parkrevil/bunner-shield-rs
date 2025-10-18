use super::super::trusted_types;
use super::super::utils::contains_token;
use crate::csp::options::{CspDirective, CspOptions, TrustedTypesPolicy, TrustedTypesToken};

pub struct TrustedTypesBuilder<'a> {
    options: &'a mut CspOptions,
}

impl<'a> TrustedTypesBuilder<'a> {
    pub(crate) fn new(options: &'a mut CspOptions) -> Self {
        Self { options }
    }

    pub fn tokens<I>(self, tokens: I) -> Self
    where
        I: IntoIterator<Item = TrustedTypesToken>,
    {
        let value = trusted_types::render_tokens(tokens);
        self.options
            .set_directive(CspDirective::TrustedTypes.as_str(), &value);
        self
    }

    pub fn policies<I>(self, policies: I) -> Self
    where
        I: IntoIterator<Item = TrustedTypesPolicy>,
    {
        self.tokens(policies.into_iter().map(TrustedTypesToken::from))
    }

    pub fn policy(mut self, policy: TrustedTypesPolicy) -> Self {
        self.add_token(policy.into_string());
        self
    }

    pub fn token(mut self, token: TrustedTypesToken) -> Self {
        self.add_token(token.into_string());
        self
    }

    pub fn allow_duplicates(self) -> Self {
        self.token(TrustedTypesToken::AllowDuplicates)
    }

    pub fn none(self) -> Self {
        self.options
            .set_directive(CspDirective::TrustedTypes.as_str(), "'none'");
        self
    }

    fn add_token(&mut self, token: String) {
        if token.is_empty() {
            return;
        }

        let directive = CspDirective::TrustedTypes.as_str();

        if let Some((_, existing)) = self
            .options
            .directives
            .iter_mut()
            .find(|(name, _)| name == directive)
            && contains_token(existing, "'none'")
        {
            existing.clear();
        }

        self.options.add_directive_token(directive, &token);
    }
}
