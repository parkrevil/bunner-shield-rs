# HSTS (Strict-Transport-Security)

사이트에 대한 강제 HTTPS 정책을 브라우저에 고지합니다. 헤더: `Strict-Transport-Security`.

## 옵션 요약
- `max-age`, `includeSubDomains`, `preload` 지원
- `preload`는 서브도메인 필수, 충분히 긴 `max-age` 필요

## 예시
```rust
use bunner_shield_rs::prelude::*;
let hsts = HstsOptions::new();
let shield = Shield::builder().hsts(hsts).build();
```