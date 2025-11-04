# Permissions-Policy

브라우저 기능(센서, 카메라 등)의 사용 범위를 출처별로 제한합니다. 헤더: `Permissions-Policy`.

## 옵션 요약
- 정책 문자열 직접 지정 또는 빌더 제공
- 허용 목록 항목: `self`, `*`(일부 기능), 특정 origin, `()`(없음)
- 기본은 origin에 큰따옴표 적용(권장). 레거시 비따옴표 모드 지원
- 빈 정책 금지(검증). 기능명 유효성 검사 포함
- Report-Only 모드 지원: `Permissions-Policy-Report-Only` 키 사용

## 예시
```rust
use bunner_shield_rs::prelude::*;

// 1) 직접 정책 문자열 지정
let pp = PermissionsPolicyOptions::new("geolocation=(self \"https://example.com\")");
let shield = Shield::builder().permissions_policy(pp).build();
```

### 빌더 사용 예시(권장)
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::permissions_policy::{AllowListItem, PermissionsPolicyOptions};

let opts = PermissionsPolicyOptions::builder()
		.feature("geolocation", [
				AllowListItem::SelfKeyword,
				AllowListItem::Origin("https://maps.example".into()),
		])
		.feature("camera", [AllowListItem::None]) // camera=()
		.feature("fullscreen", [AllowListItem::Any]) // fullscreen=(*)
		.build()
		.expect("valid policy");

let shield = Shield::builder().permissions_policy(opts).build();
```

### Report-Only 모드
```rust
use bunner_shield_rs::prelude::*;
let opts = PermissionsPolicyOptions::new("geolocation=(self)").report_only();
let shield = Shield::builder().permissions_policy(opts).build();
// 헤더 키는 Permissions-Policy-Report-Only 로 전송됩니다.
```

## API 개요
- `PermissionsPolicyOptions::new(policy: impl Into<String>)`
- `.policy(string)` — 문자열 교체
- `.report_only()` — 보고 전용 모드
- `.builder()` — 정책 빌더 시작
	- `feature(name, allowlist)` — 기능과 허용 항목 지정
		- AllowListItem::None → `()`
		- AllowListItem::SelfKeyword → `self`
		- AllowListItem::Any → `*`
		- AllowListItem::Origin("https://a.example") → 기본으로 큰따옴표 적용
	- `.legacy_unquoted_origins()` — 기원 토큰에서 따옴표 제거(레거시 호환)
	- `.build()` → `PermissionsPolicyOptions` 생성

검증 및 직렬화
- 기능명 정규화: 소문자, 숫자, `-`만 허용하며 문자로 시작해야 함
- 허용 목록 중복 제거, 공백/빈 항목 에러 처리
- 렌더링 결과: `feature=(items...)` 목록을 `, `로 연결

## 권장 설정
- 처음에는 Report-Only로 시작해 위반 로그를 모은 후 강제 모드로 전환하세요.
- Origin 토큰은 기본 큰따옴표 모드를 유지하세요(파서 호환성 및 명확성).
- 최소 권한 원칙: 필요 기능만 `self` 또는 좁은 origin으로 한정하세요.
- 광범위 허용(`*`)은 피하고, 부득이한 경우에만 사용하세요.

## 주의 사항
- 기능별 지원 여부, 허용 목록 의미는 브라우저 구현에 따릅니다.
- 사이트 내 iframe/서브리소스 상호작용을 고려해 기능 범위를 설계하세요.