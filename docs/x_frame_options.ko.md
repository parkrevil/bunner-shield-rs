# X-Frame-Options

프레이밍을 제한합니다. `DENY` 또는 `SAMEORIGIN`.

> ALLOW-FROM 는 비표준/비권장. 대체로 CSP `frame-ancestors` 사용 권장.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let xfo = XFrameOptionsOptions::new();
let shield = Shield::builder().x_frame_options(xfo).build();
```