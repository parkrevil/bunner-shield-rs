# Fetch Metadata

교차 출처 공격을 줄이기 위해 요청의 출처 맥락(Sec-Fetch-*)을 검사하고 정책을 적용합니다.

## 옵션 요약
- 내비게이션/서브리소스/프리플라이트 등 목적지 제어
- 크로스 사이트 허용 규칙 추가
- 위반 훅(on_violation)으로 텔레메트리 전송 가능

## 예시
```rust
use bunner_shield_rs::prelude::*;
let fm = FetchMetadataOptions::new();
let shield = Shield::builder().fetch_metadata(fm).build();
```