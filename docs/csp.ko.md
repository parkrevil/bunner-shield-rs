# CSP (Content-Security-Policy)

스크립트·스타일·이미지 등의 로딩 출처를 화이트리스트로 제한합니다. 기본 보안 헤더는 `Content-Security-Policy`(강제)와 `Content-Security-Policy-Report-Only`(리포트 전용)입니다.

## 옵션 요약
- 기본 지시문: `default-src`, `script-src`, `style-src`, `img-src`, `font-src`, `connect-src`, `frame-ancestors` 등
- 신뢰 토큰: nonce/hash 지원 (런타임 nonce 매니저 포함)
- 리포트 전용 모드: `.report_only(true)`
- 병합/중복 제거, 표준 직렬화 순서 보장

## 예시
```rust
use bunner_shield_rs::prelude::*;

let csp = CspOptions::new()
    .default_src([CspSource::Self_])
    .script_src([CspSource::Self_]);

let shield = Shield::builder().csp(csp).build();
```