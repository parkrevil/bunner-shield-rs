# Clear-Site-Data

민감한 동작(로그아웃, 계정 삭제, 권한 하향 조정 등) 이후 브라우저 측 사용자 데이터를 안전하게 정리하도록 지시하는 응답 헤더입니다. 선택한 범주에 따라 캐시, 쿠키, 웹 스토리지, 실행 컨텍스트를 정리하여 잔존 세션이나 민감 데이터의 남용 가능성을 줄입니다.

## 옵션 요약
- 지원 범주: `"cache"`, `"cookies"`, `"storage"`, `"executionContexts"`
- 최소 하나 이상의 범주를 선택해야 하며, 그렇지 않으면 검증 에러가 발생합니다.
- 라이브러리는 값 병합/중복 제거와 안정적인 직렬화 순서를 보장합니다.
- 브라우저는 보안 컨텍스트(HTTPS)에서만 의미 있게 처리하는 것이 일반적이며, 일부 범주는 브라우저별로 지원이 제한될 수 있습니다.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let csd = ClearSiteDataOptions::new()
	.cookies()
	.storage()
	.execution_contexts();
let shield = Shield::builder().clear_site_data(csd).build();
```

## 언제 사용하나요?
- 로그아웃 직후: 세션 쿠키와 스토리지에 남은 토큰/설정을 제거해 재사용을 방지합니다.
- 계정 삭제·탈퇴: 쿠키·스토리지·캐시·실행 컨텍스트까지 넓게 정리해 흔적을 최소화합니다.
- 권한 축소(관리자 → 일반): 이전 권한이 반영된 캐시/스토리지의 부작용을 줄입니다.
- 보안 사고 대응: 세션 탈취·CSRF 의심 등에서 사용자 단 데이터를 신속히 정리합니다.

## 동작 방식
브라우저는 응답의 `Clear-Site-Data` 값을 해석해 현재 출처(origin)에 대한 데이터를 정리합니다. 정리는 즉시 혹은 비동기적으로 이루어질 수 있으며, 같은 응답에서 설정한 새 `Set-Cookie`도 정리 대상에 포함될 수 있습니다. 따라서 아래의 2단계 패턴을 권장합니다.

1) 정리 전용 응답에서 `Clear-Site-Data`만 보내고 302/303으로 리디렉션
2) 도착 페이지에서 새로운 세션/설정을 수립

## 옵션(범주) 상세
- cache: HTTP 캐시 및 브라우저 캐시된 리소스를 정리합니다. 범위가 커질수록 비용이 커질 수 있습니다.
- cookies: 현재 출처와 관련된 쿠키를 정리합니다. 로그아웃 효과가 있으며 새로 설정한 쿠키도 제거될 수 있습니다.
- storage: localStorage, sessionStorage, IndexedDB, Cache Storage 등 클라이언트 스토리지를 정리합니다.
- executionContexts: 가능한 경우 활성 실행 컨텍스트(탭/프레임 등)의 리로드·초기화를 유도합니다. 브라우저별 편차가 있을 수 있습니다.

참고: 실제 정리 범위와 시점은 브라우저 구현에 따라 다를 수 있습니다. 사용자 영향(로그아웃, 오프라인 데이터 손실 등)을 미리 고지하세요.

## 권장 설정 가이드
- 로그아웃: `cookies` + `storage` (+ `executionContexts` 상황에 따라)
- 계정 삭제/중대한 보안 이벤트: `cache` + `cookies` + `storage` + `executionContexts`
- 민감 설정 초기화: `storage` 단독 또는 `cookies`와 병행

매 요청에 일괄 적용하는 것은 사용자 경험과 성능 모두에 악영향을 줄 수 있습니다. 특정 이벤트에서만 사용하세요.

## 단계적 재설정(권장 패턴)
```rust
use bunner_shield_rs::prelude::*;

// 1) /logout 응답에서 Clear-Site-Data만 적용하고 302/303 리디렉션
let logout_csd = ClearSiteDataOptions::new().cookies().storage().execution_contexts();
let shield = Shield::builder().clear_site_data(logout_csd).build();
let logout_headers = shield.secure(base_headers)?; // Location 포함

// 2) 리디렉션 도착 후 새 세션(Set-Cookie) 수립
```

## API 참고
- ClearSiteDataOptions::new()
- .cache() · .cookies() · .storage() · .execution_contexts()
- 검증: 최소 한 개의 범주가 필요하며, 없을 경우 `ClearSiteDataOptionsError::NoSectionsSelected`
- Shield 통합: `Shield::builder().clear_site_data(options)` 또는 즉시 검증 경로 `Shield::new().clear_site_data(options)?`

## 오류 및 유효성 검사
- 선택된 범주가 없으면 기능 추가 시점 또는 `secure()`에서 검증 에러가 발생합니다.
- Builder는 검증을 `secure()` 시점으로 지연하여 런타임 구성에 유리합니다.

## 주의 사항 및 한계
- 브라우저 지원은 범주별·버전별로 차이가 있습니다. 특히 `executionContexts`는 부분 동작 가능성이 있습니다.
- HTTPS가 아닌 응답에서는 무시되거나 제한적으로 동작할 수 있습니다.
- 같은 응답에서 `Set-Cookie`를 사용하는 경우 새 쿠키가 제거될 수 있으므로, 리디렉션을 통한 단계적 적용을 추천합니다.
- 서브도메인 전체 정리를 가정하지 마세요. 필요 시 각 출처에서 별도로 적용해야 할 수 있습니다.

## 테스트 팁
```rust
let opts = ClearSiteDataOptions::new().cache().cookies().storage().execution_contexts();
let shield = Shield::new().clear_site_data(opts)?;
let res = shield.secure(headers)?;
assert_eq!(
		res.get("Clear-Site-Data").map(String::as_str),
		Some("\"cache\", \"cookies\", \"storage\", \"executionContexts\"")
);
```

## FAQ
- Q. 매 요청마다 넣어도 되나요?
	- A. 권장하지 않습니다. 비용이 크고 UX에 악영향을 줍니다. 특정 이벤트에서만 사용하세요.
- Q. Set-Cookie와 함께 사용해도 안전한가요?
	- A. 같은 응답에서 새로 설정한 쿠키가 정리될 수 있습니다. 정리 → 리디렉션 → 새 세션 수립 순서를 권장합니다.
- Q. 브라우저별 동작 차이는 없나요?
	- A. 있습니다. 특히 `executionContexts`와 일부 스토리지 정리는 구현 차가 있을 수 있습니다. 최신 호환성 정보를 확인하세요.

---
이 문서는 일정한 톤·형식을 유지하며 핵심 개념 → 옵션 → 권장 설정 → 예시 → 한계/FAQ 순으로 구성되어 있습니다. 요구 사항에 맞게 최소 범주만 선택해 예측 가능하게 적용하세요.