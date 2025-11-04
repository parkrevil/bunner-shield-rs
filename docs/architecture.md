# Architecture and Module Structure

This document explains the high-level architecture of bunner-shield-rs and the rationale behind its module structure and public APIs.

## Overview

bunner-shield-rs is a composable HTTP response hardening library. It provides a set of features (headers or behaviors) that can be applied to a normalized header map through a pipeline called `Shield`.

- Normalization: Incoming headers are normalized into a case-insensitive, canonical structure to make feature composition predictable and idempotent.
- Composition: Each feature implements a common `Executor` interface and can be registered with the `Shield`.
- Execution: The `Shield` validates options, then executes features in priority order, returning updated headers or an error.

## Key Modules

- `normalized_headers`: Case-insensitive header map that preserves canonical casing and supports multi-value semantics for `Set-Cookie`.
- `executor`: Trait and helpers used by all features to validate options and execute against headers.
- Feature modules:
  - `csp`, `permissions_policy`, `referrer_policy`, `hsts`, `coep`, `coop`, `corp`, `origin_agent_cluster` — standards-aligned security headers with option builders and strict validation.
  - `csrf` — runtime token issuance and verification, plus a response header cookie injector.
  - `fetch_metadata` — request-side evaluation and policy with an optional violation hook.
  - `x_*` and `safe_headers` — classic hardening headers and sanitization passes.
- `shield`: The composition pipeline. Provides fluent feature registration, a builder API with deferred validation, and pre-execution validation for fast feedback.

## Error Handling

- `ShieldError` is the common error surface for pipeline operations. Errors are categorized via `ShieldErrorKind` (Validation | Execution), and source chains are preserved for debugging.
- Feature modules expose their own strongly typed option errors; these are wrapped when surfaced through `Shield`.
- `ShieldResult<T>` is a convenient alias used across public APIs that return `ShieldError`.

## Public API and Prelude

`lib.rs` re-exports commonly used types for ergonomics. To keep the top-level API approachable while avoiding a very wide surface, a `prelude` module exposes the types most users need:

```rust
use bunner_shield_rs::prelude::*;
```

The intent is to gradually prefer the prelude for most use cases and consider reducing top-level re-exports in a future minor release (with changelog guidance).

## Builder and Deferred Validation

`Shield::builder()` collects features without validating immediately. Validation occurs at `secure()` time before any header modifications, surfacing misconfigurations early and consistently.

- Fluent methods return `Self` for chaining.
- `build()` returns a `Shield` that can be reused across requests.

## Determinism and Idempotence

- Normalized header ordering and feature execution order are designed to be deterministic. Features that may be invoked multiple times cache static header values.
- Multi-value semantics (e.g., `Set-Cookie`) are handled explicitly to avoid accidental value merging.

## Performance Considerations

- Most features pre-render static header values and reuse them across calls.
- The pipeline minimizes allocations by reusing structures and writing in place when possible.
- Property-based tests cover idempotence and ordering guarantees for critical modules.

## Extensibility Guidelines

- New features should implement the `Executor` trait, expose an options type with `validate()`, and provide precise error types.
- Keep runtime logic small; prefer precomputation during option building/validation.
- Document security tradeoffs and defaults in Rustdoc and under `docs/`.

## Future Work

- Narrow top-level exports in favor of `prelude`.
- Optional feature flags to reduce dependency footprint (e.g., `csrf`).
- Additional examples for common web frameworks (Axum, Actix-web, Rocket).
