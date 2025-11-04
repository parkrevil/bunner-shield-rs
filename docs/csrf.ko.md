# CSRF 보호

더블 서브밋 쿠키 기반, HMAC 토큰(v2) 기본. 만료를 포함하며 서버 상태 없이 검증 가능합니다.

## 옵션 요약
- 허용 출처 화이트리스트(`allowed_origins`)
- `origin_validation(use_referer)`로 Origin/Referer 검증
- 재사용 방지 저장소(선택)

## 예시
```rust
use bunner_shield_rs::prelude::*;
let csrf = CsrfOptions::new([0u8; 32])
    .origin_validation(true, true)
    .allowed_origins(["https://app.example.com"]);
let shield = Shield::builder().csrf(csrf).build();
```