# Permissions-Policy

브라우저 기능(센서, 카메라 등)의 사용 범위를 출처별로 제한합니다. 헤더: `Permissions-Policy`.

## 옵션 요약
- 기능 이름과 허용 목록( `self`, 특정 origin )
- 기본은 origin에 큰따옴표 적용 (레거시 모드로 비활성화 가능)
- 빈 정책 금지(검증)

## 예시
```rust
use bunner_shield_rs::prelude::*;

// 간단 예시: 직접 정책 문자열을 구성
let pp = PermissionsPolicyOptions::new().policy("geolocation=(self \"https://example.com\")");
let shield = Shield::builder().permissions_policy(pp).build();
```