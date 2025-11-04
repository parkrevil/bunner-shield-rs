# COEP (Cross-Origin-Embedder-Policy)

다른 출처 리소스 임베드 시의 격리 모드를 제어합니다. 헤더: `Cross-Origin-Embedder-Policy`.

## 옵션 요약
- `require-corp`, `credentialless` 지원
- 리포트 전용 모드 가능

## 예시
```rust
use bunner_shield_rs::prelude::*;
let coep = CoepOptions::new();
let shield = Shield::builder().coep(coep).build();
```