# CORP (Cross-Origin-Resource-Policy)

다른 출처에서 현재 출처 리소스를 어떻게 사용할 수 있는지 제어합니다. 헤더: `Cross-Origin-Resource-Policy`.

## 옵션 요약
- `same-origin`, `same-site`, `cross-origin`

## 예시
```rust
use bunner_shield_rs::prelude::*;
let corp = CorpOptions::new();
let shield = Shield::builder().corp(corp).build();
```