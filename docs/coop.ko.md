# COOP (Cross-Origin-Opener-Policy)

윈도우 오프너 관계를 제어하여 격리를 강화합니다. 헤더: `Cross-Origin-Opener-Policy`.

## 옵션 요약
- `same-origin`, `same-origin-allow-popups`, `unsafe-none`
- 리포트 전용 모드 가능

## 예시
```rust
use bunner_shield_rs::prelude::*;
let coop = CoopOptions::new();
let shield = Shield::builder().coop(coop).build();
```