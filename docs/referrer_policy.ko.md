# Referrer-Policy

요청에 첨부되는 Referer 정보의 범위를 제어합니다. 헤더: `Referrer-Policy`.

## 옵션 요약
- 주요 값: `no-referrer`, `same-origin`, `strict-origin-when-cross-origin`(권장 기본)
- 다중 값 지원 (쉼표 구분)

## 예시
```rust
use bunner_shield_rs::prelude::*;
let rp = ReferrerPolicyOptions::new().strict_origin_when_cross_origin();
let shield = Shield::builder().referrer_policy(rp).build();
```