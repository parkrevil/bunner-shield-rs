# X-Content-Type-Options

MIME 스니핑을 방지합니다. 헤더: `X-Content-Type-Options: nosniff`.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let shield = Shield::builder().x_content_type_options(()).build();
```

## 동작
- 모든 응답에 `X-Content-Type-Options: nosniff`를 설정해, 브라우저가 선언된 `Content-Type`을 일관되게 따르도록 합니다.
- 잘못된 MIME으로 스크립트/스타일을 제공하는 경우 로드가 차단될 수 있으므로, 정적 파일의 `Content-Type`을 올바르게 설정해야 합니다.

## 권장 사항
- 기본적으로 항상 활성화하세요.
- 자산 서버/리버스 프록시에서 MIME 타입을 정확히 설정하여 예상치 못한 차단을 방지하세요.