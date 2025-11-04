# SameSite 쿠키 업그레이드

`Set-Cookie` 헤더를 정규화하고 `Secure`/`HttpOnly`/`SameSite` 속성을 강제합니다. 필요 시 Path/Domain/Max-Age를 추가합니다.

## 옵션 요약
- 기본 정책(Lax, Secure, HttpOnly 기본)
- 쿠키 이름별 정책 오버라이드
- 누락 시 Path/Domain/Max-Age 강제

## 예시
```rust
use bunner_shield_rs::prelude::*;
let same_site = SameSiteOptions::new()
    .map_policy_for_cookie("session", SameSitePolicy::Strict)
    .enforce_path("/");
let shield = Shield::builder().same_site(same_site).build();
```