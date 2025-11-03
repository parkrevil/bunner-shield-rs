# CSRF protection: stateless defaults and options

This library implements a double-submit-cookie CSRF scheme with secure defaults that work in fully stateless deployments.

- Tokens are HMAC-signed and versioned.
  - v2 tokens embed a timestamp, so expiry is enforced without any server-side storage.
  - Legacy v1 tokens are rejected by default (`MissingTimestamp`) to avoid unbounded validity.
- A cookie is issued alongside a response header. Clients should echo the header token on state-changing requests.
- Optional replay protection is available if you connect a `CsrfReplayStore` (in-memory for tests, Redis via the `csrf-redis` feature for production). This is off by default to keep the scheme stateless; enable it if you need one-time tokens.

## Origins allow list

Modern CSRF defenses should include strict origin checks for state-changing requests.

- Use `CsrfOptions::allowed_origins(["https://app.example.com", ...])` to configure an explicit allow list.
- Enable validation via `origin_validation(true, use_referer)`.
  - If `use_referer` is true, a matching `Referer` is accepted as a fallback when `Origin` is missing (older browsers, some redirects).
  - Host-derived inference is not supported; be explicit about allowed origins.

## Verification API

- `HmacCsrfService::verify(token)`
  - Default path that enforces expiry for v2 tokens using an internal clock.
- `HmacCsrfService::verify_with_max_age(token, max_age_secs, now_secs)`
  - When you need to customize lifetime or pass a fixed `now` (e.g., deterministic tests).
- `HmacCsrfService::verify_signature_only(token)`
  - Integrity-only check (no expiry, no replay). For diagnostics and special flows, not for normal request validation.
- `HmacCsrfService::verify_and_consume(token, store)`
  - Enforces expiry and uniqueness by consuming token IDs in a replay store. Use with Redis for one-time tokens.

## Stateless nonce guidance

Tokens include a timestamp and a monotonic nonce, yielding sufficient entropy without keeping server state. For most apps:

- Keep the default 2-hour max age.
- Regenerate and set a fresh token each response; clients should send it back via header or form field.
- Only enable a replay store if you require single-use semantics (e.g., highly sensitive operations).

## Example

```rust
use bunner_shield_rs::csrf::CsrfOptions;
use bunner_shield_rs::shield::Shield;

let shield = Shield::new()
    .csrf(
        CsrfOptions::new([0u8; 32])
            .origin_validation(true, true)
            .allowed_origins(["https://app.example.com"]) // explicit allow list
    )?
    .build()?; // if using a builder pattern
```

See also: `src/csrf/mod.rs` rustdoc for a quick overview and `tests/csrf.rs` for usage patterns.
