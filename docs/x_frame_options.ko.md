# X-Frame-Options

프레이밍(iframe 삽입)을 제한합니다. 값: `DENY` 또는 `SAMEORIGIN`.

> ALLOW-FROM 는 비표준/비권장. 대체로 CSP `frame-ancestors` 사용 권장.

## 예시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::x_frame_options::XFrameOptionsPolicy as P;

// 기본값 DENY
let xfo = XFrameOptionsOptions::new();
let shield = Shield::builder().x_frame_options(xfo).build();

// SAMEORIGIN으로 완화
let xfo = XFrameOptionsOptions::new().policy(P::SameOrigin);
let shield = Shield::builder().x_frame_options(xfo).build();
```

## 권장 사항
- 최신 브라우저를 대상으로 한다면 CSP `frame-ancestors`를 우선 설정하고, 보조 수단으로 X-Frame-Options를 병행하세요.
- 기본은 `DENY`, 동일 출처에서만 프레이밍이 필요한 경우에만 `SAMEORIGIN`을 사용하세요.