# X-Content-Type-Options

MIME 스니핑을 방지합니다. 헤더: `X-Content-Type-Options: nosniff`.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let shield = Shield::builder().x_content_type_options(()).build();
```