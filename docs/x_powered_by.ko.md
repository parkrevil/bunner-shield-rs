# X-Powered-By 제거

서버 프레임워크 식별 헤더를 제거합니다.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let shield = Shield::builder().x_powered_by(()).build(); // 옵션 없음
```