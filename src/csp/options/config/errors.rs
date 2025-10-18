use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CspOptionsError {
    #[error("missing directives")]
    MissingDirectives,
    #[error("invalid directive name")]
    InvalidDirectiveName,
    #[error("invalid directive value")]
    InvalidDirectiveValue,
    #[error("invalid directive token")]
    InvalidDirectiveToken,
    #[error("invalid nonce source expression")]
    InvalidNonce,
    #[error("invalid hash source expression")]
    InvalidHash,
    #[error("'strict-dynamic' requires at least one nonce or hash source")]
    StrictDynamicRequiresNonceOrHash,
    #[error("'strict-dynamic' cannot be combined with unsafe-inline/unsafe-eval/unsafe-hashes")]
    StrictDynamicConflicts,
    #[error("'none' token cannot be combined with other sources")]
    ConflictingNoneToken,
    #[error("sandbox directive contains invalid token `{0}`")]
    InvalidSandboxToken(String),
    #[error("invalid source expression `{0}`")]
    InvalidSourceExpression(String),
    #[error("token `{0}` is not allowed in directive `{1}`")]
    TokenNotAllowedForDirective(String, String),
    #[error("'unsafe-hashes' in `{0}` requires at least one hash source expression")]
    UnsafeHashesRequireHashes(String),
    #[error("scheme `{1}` is not permitted in directive `{0}`")]
    DisallowedScheme(String, String),
    #[error("source expression `{0}` cannot use a wildcard port")]
    PortWildcardUnsupported(String),
    #[error("'strict-dynamic' cannot be combined with host or scheme sources")]
    StrictDynamicHostSourceConflict,
}
