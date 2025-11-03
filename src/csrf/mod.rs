//! CSRF protection utilities.
//!
//! This module implements a stateless double-submit-cookie CSRF scheme by default:
//! - Tokens are HMAC-signed and include a timestamp (v2), so verification enforces expiry without server state.
//! - A cookie is issued alongside a response header so clients can echo the token on state-changing requests.
//! - Optional replay protection is available via a `CsrfReplayStore` (in-memory or Redis with the `csrf-redis` feature),
//!   but it is not required for correctness and can be omitted for fully stateless operation.
//!
//! Origin verification:
//! - Configure an explicit allow list using [`CsrfOptions::allowed_origins`]. When enabled with
//!   [`CsrfOptions::origin_validation(true, use_referer)`], incoming requests must present an `Origin` that matches the
//!   allow list, or if `use_referer` is true, a matching `Referer` will be accepted as a fallback for legacy clients.
//!
//! Verification behavior:
//! - [`HmacCsrfService::verify`] enforces expiry by default for v2 tokens using an internal clock.
//! - [`HmacCsrfService::verify_with_max_age`] allows customizing the max age and passing an explicit `now` when needed.
//! - [`HmacCsrfService::verify_signature_only`] checks integrity only and should be reserved for diagnostics/special flows.
//!
//! See `docs/csrf.md` for integration tips, stateless vs stateful trade-offs, and recommended settings.

mod executor;
mod options;
mod origin;
mod token;

pub use executor::{Csrf, CsrfError};
pub use options::{CsrfOptions, CsrfOptionsError};
pub use token::{CsrfReplayStore, CsrfTokenError, HmacCsrfService, InMemoryReplayStore};

#[cfg(feature = "csrf-redis")]
mod replay_store_redis;
#[cfg(feature = "csrf-redis")]
pub use replay_store_redis::RedisReplayStore;
