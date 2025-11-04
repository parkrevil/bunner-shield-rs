# Clear-Site-Data

로그아웃 등 민감 동작 후 캐시·쿠키·스토리지 등 클라이언트 데이터를 정리합니다.

## 옵션 요약
- `cache`, `cookies`, `storage`, `executionContexts`
- 중복 제거 및 표준 순서 직렬화

## 예시
```rust
use bunner_shield_rs::prelude::*;
let csd = ClearSiteDataOptions::new().cache().cookies();
let shield = Shield::builder().clear_site_data(csd).build();
```