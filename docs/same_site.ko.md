# SameSite 쿠키 업그레이드

`Set-Cookie` 헤더를 정규화하고 `Secure`/`HttpOnly`/`SameSite` 속성을 강제합니다. 필요 시 Path/Domain/Max-Age를 추가합니다.

## 옵션 요약
- 기본 정책(Lax, Secure, HttpOnly 기본)
- 쿠키 이름별 정책 오버라이드
- 누락 시 Path/Domain/Max-Age 강제

기본값
- Default 메타: Secure=true, HttpOnly=true, SameSite=Lax
- SameSite=None을 사용하는 경우 반드시 Secure=true가 필요합니다(검증됨)

## 예시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::same_site::SameSitePolicy;

// 기본 설정: 모든 쿠키에 Secure/HttpOnly, SameSite=Lax 적용
let same_site = SameSiteOptions::new()
    .enforce_path("/") // Path 없으면 강제
    .enforce_domain("example.com") // Domain 없으면 강제
    .enforce_max_age(60 * 60 * 24 * 7); // 7일

// 특정 쿠키만 정책 오버라이드
let same_site = same_site
    .map_policy_for_cookie("session", SameSitePolicy::Strict)
    .enforce_path_for_cookie("session", "/app");
let shield = Shield::builder().same_site(same_site).build();
```

### SameSite=None 사용 시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::same_site::SameSitePolicy;

// SameSite=None은 Secure=true가 반드시 요구됩니다(옵션 검증에서 에러 처리)
let same_site = SameSiteOptions::new()
    .same_site(SameSitePolicy::None) // default 정책 변경
    .secure(true); // 필수

let shield = Shield::builder().same_site(same_site).build();
```

## 동작 방식
- Set-Cookie 값을 파싱해 기존 `Secure`/`HttpOnly`/`SameSite` 속성은 제거하고 정책에 맞게 재적용합니다.
- Path/Domain/Max-Age는 “누락된 경우에만” 옵션에서 지정한 값을 강제 추가합니다(이미 있으면 보존).
- 쿠키 개별 오버라이드는 이름 매칭으로 적용됩니다.

## 권장 사항
- 세션/민감 쿠키에는 최소 `SameSite=Lax`, `Secure`, `HttpOnly`를 유지하세요.
- 크로스 사이트 신뢰된 플로우(예: 외부 결제 리턴)에만 `SameSite=None; Secure`를 사용하세요.
- Path/Domain/Max-Age 강제는 서비스의 표준 값을 일관되게 유지하는 데 유용합니다.