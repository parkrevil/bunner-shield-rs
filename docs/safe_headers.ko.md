# 안전 헤더 정리 (Safe Headers)

제어 문자 등 위험한 값을 정리(sanitize)하여 헤더 인젝션 위험을 줄입니다.

## 동작
- 정상 키/값만 유지, 다중 값 헤더는 표준 규칙에 따라 분리/병합

## 예시
```rust
use bunner_shield_rs::prelude::*;
let shield = Shield::builder().safe_headers(()).build(); // 옵션 없음
```