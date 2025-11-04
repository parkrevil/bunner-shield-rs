# Fetch Metadata

요청의 출처 맥락을 나타내는 `Sec-Fetch-*` 헤더를 검사해 교차 출처 공격을 줄이는 정책입니다. 브라우저가 제공하는 `Sec-Fetch-Site`/`Mode`/`Dest`/`User` 신호를 조합해, 교차 사이트 요청을 안전한 경우에만 허용합니다.

기본 전략
- same-origin / same-site: 허용
- cross-site: 기본 차단(정책 예외 또는 탐색 허용 조건을 만족하면 허용)
- 레거시 클라이언트: 기본 허용(헤더 부재 시), 필요시 차단으로 변경 가능

## 옵션 요약
- 탐색 허용: `.allow_navigation_requests(true)` — 기본 허용
- 사용자 활성화 필요: `.require_user_activation_for_navigation(true)` — 기본 필요
- 레거시 허용: `.allow_legacy_clients(true)` — 기본 허용(헤더 부재 허용)
- 허용 탐색 목적지: `.navigation_destinations([Document, NestedDocument])` — 기본값
- 교차 사이트 허용 규칙: `.allow_cross_site_rule(FetchMetadataRule::new().mode(...).destination(...))`
- 위반 훅: `.on_violation(|ev| { /* telemetry */ })` — 차단 시 호출되는 콜백

## 동작 방식
1) `Sec-Fetch-Site` 파싱: none/same-origin/same-site는 허용. cross-site면 추가 평가로 이동
2) cross-site 평가:
   - `Sec-Fetch-Mode` 없는 경우 차단
   - 탐색 허용 조건(모드=navigate && 사용자 활성화(옵션) && 목적지 허용) 충족 시 허용
   - 교차 사이트 허용 규칙에 일치하면 허용
   - 나머지는 차단하며, 구성된 경우 `on_violation` 훅 호출 후 에러 반환
3) 레거시: `Sec-Fetch-*` 부재 시 `.allow_legacy_clients(true)`면 허용, 아니면 차단

지원 값
- Site: none | same-origin | same-site | cross-site | 기타(차단)
- Mode: cors | no-cors | navigate | same-origin | websocket | 기타
- Dest: document | script | style | image | frame | worker | nested-document ...

## 권장 설정 가이드
- 탐색: 기본값 유지 — 사용자 활성화를 요구하고, 문서/중첩 문서 목적지만 허용
- 레거시: 점진 도입을 위해 우선 허용 유지, 충분히 채택 후 차단 고려
- 허용 규칙: 정말 필요한 교차 사이트 경로만 최소화하여 등록(예: WebSocket, 결제 리디렉션 등)
- 관찰: `on_violation` 훅으로 차단 이벤트를 수집해 허용 규칙을 보정
- 병행: CSRF/COEP/COOP/CORS와 함께 사용해 다층 방어 구성

## 사용 예시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::fetch_metadata::{FetchMetadataRule, FetchMode, FetchDestination};

fn log_violation(ev: &FetchMetadataViolation) {
	// telemetry.emit(ev.site, ev.mode, ev.destination)
}

let fm = FetchMetadataOptions::new()
	.allow_navigation_requests(true)
	.require_user_activation_for_navigation(true)
	.allow_cross_site_rule(
		FetchMetadataRule::new().mode(FetchMode::Websocket)
	)
	.on_violation(log_violation);

let shield = Shield::builder().fetch_metadata(fm).build();
```

## API 참고
- FetchMetadataOptions::new()
- .allow_navigation_requests(bool)
- .require_user_activation_for_navigation(bool)
- .allow_legacy_clients(bool)
- .navigation_destinations([FetchDestination]) / .add_navigation_destination(FetchDestination)
- .allow_cross_site_rule(FetchMetadataRule) / .allow_cross_site_rules([...])
- .on_violation(fn(&FetchMetadataViolation))

## 주의 사항 및 한계
- 헤더 값은 브라우저가 제공하므로, 비표준 클라이언트/봇/프록시 환경에서는 신호가 부정확할 수 있습니다.
- 레거시 허용을 끄면, 헤더가 없는 합법적 요청도 차단될 수 있습니다. 점진 도입을 권장합니다.
- 허용 규칙을 과도하게 열면 보안 이점이 줄어듭니다. 최소 권한 원칙을 따르세요.

## 테스트 팁
```rust
let fm = FetchMetadataOptions::new();
let shield = Shield::builder().fetch_metadata(fm).build();
let res = shield.secure(headers)?; // 정책 위반 시 에러로 식별
```