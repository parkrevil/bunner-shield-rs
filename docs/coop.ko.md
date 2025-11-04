# COOP (Cross-Origin-Opener-Policy)

탭/창 사이의 opener 관계를 제어해 브라우징 컨텍스트 그룹을 격리하는 응답 헤더입니다. COOP는 `window.opener` 공유와 같은 교차 출처 간 상호작용을 차단해 탭 납치(tabnabbing)·정보 누출 등을 줄이며, COEP와 함께 교차 출처 격리(cross-origin isolation)를 달성하는 핵심 구성 요소입니다.

관련 헤더 키:
- 강제: `Cross-Origin-Opener-Policy`
- 리포트 전용: `Cross-Origin-Opener-Policy-Report-Only`

## 옵션 요약
- 지원 정책: `same-origin`(기본), `same-origin-allow-popups`, `unsafe-none`
- 모드: 강제(enforce, 기본), 리포트 전용(report-only)
- 표준 직렬화 및 모드에 따른 헤더 키 자동 전환

## 언제 사용하나요?
- 교차 출처 격리를 달성하여 SharedArrayBuffer 등 고급 기능을 사용해야 할 때 (COEP와 병행)
- opener 공유를 통한 탭 납치/참조 누출을 줄이고자 할 때
- 외부로 팝업을 열지만 탭 간 강한 격리를 유지하려 할 때

## 동작 방식
COOP는 현재 문서가 속한 브라우징 컨텍스트 그룹(BCG)을 어떻게 구성할지 정의합니다.
- `same-origin`: 현재 문서를 동일 출처끼리만 묶인 새로운 BCG로 격리합니다. 교차 출처 문서와 `window.opener` 참조를 공유하지 않습니다.
- `same-origin-allow-popups`: 기본적으로 `same-origin`과 유사하게 격리하되, 현재 문서가 연 팝업들에 대해 더 관대한 호환성을 부여합니다(교차 출처 팝업과의 일부 상호작용 허용). 보안은 `same-origin`보다 느슨합니다.
- `unsafe-none`: 격리를 비활성화합니다. 과거 웹과의 호환성을 위해 존재하며 보안상 권장되지 않습니다.

일반적으로 완전한 교차 출처 격리를 원한다면 COOP(`same-origin`)과 COEP(`require-corp` 또는 `credentialless`)를 함께 설정해야 합니다.

## 모드
- 강제(Enforce, 기본): `Cross-Origin-Opener-Policy`로 즉시 정책을 적용합니다.
- 리포트 전용(Report-Only): `Cross-Origin-Opener-Policy-Report-Only`로 위반을 관찰합니다. 본 라이브러리는 리포트 전용일 때 강제 키와의 중복을 회피하도록 헤더 키를 자동 전환합니다.

## 권장 설정 가이드
- 교차 출처 격리 목표: COOP=`same-origin` + COEP=`require-corp` 조합을 권장합니다.
- 외부 팝업 호환성이 중요한 경우: `same-origin-allow-popups`를 고려하되, 보안 약화를 인지하세요.
- 레거시 호환이 반드시 필요한 경우에만 `unsafe-none`을 사용하세요(권장하지 않음).
- 단계적 도입: 먼저 리포트 전용으로 배포해 영향도를 파악한 뒤 강제 모드로 전환하세요.

## 라이브러리 통합
이 라이브러리는 COOP를 독립 기능으로 제공하며, Builder로 쉽게 조합할 수 있습니다. 문자열 파서와 리포트 전용 모드 전환을 지원합니다.

### 빠른 시작
```rust
use bunner_shield_rs::prelude::*;

// 기본(권장) 값: same-origin
let coop = CoopOptions::new();
let shield = Shield::builder().coop(coop).build();
```

### 팝업 호환 버전 사용 예
```rust
use bunner_shield_rs::prelude::*;

let coop = CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups);
let shield = Shield::new().coop(coop)?;
let res = shield.secure(headers)?;
assert_eq!(
		res.get("Cross-Origin-Opener-Policy").map(String::as_str),
		Some("same-origin-allow-popups")
);
```

### Report-Only로 점진 도입
```rust
use bunner_shield_rs::prelude::*;

let coop_ro = CoopOptions::new().report_only();
let shield = Shield::builder().coop(coop_ro).build();
let res = shield.secure(headers)?;
assert!(res.get("Cross-Origin-Opener-Policy").is_none());
assert!(res
		.get("Cross-Origin-Opener-Policy-Report-Only")
		.is_some());
```

## API 참고
- CoopOptions::new(), .policy(CoopPolicy), .policy_from_str(&str) → Result, CoopOptions::from_policy_str(&str) → Result
- .report_only()로 모드 전환 (기본은 Enforce)
- Shield 통합: `Shield::builder().coop(options)` 또는 즉시 검증 경로 `Shield::new().coop(options)?`

## 주의 사항 및 한계
- COOP만으로는 교차 출처 격리가 완성되지 않습니다. COEP와 함께 사용하세요.
- `same-origin-allow-popups`는 편의가 늘어나는 대신 보안 경계가 일부 완화됩니다. 필요한 경우에만 사용하세요.
- 일부 통합(SSO/결제 등)이 `window.opener` 공유에 의존할 수 있습니다. 리포트 전용으로 영향도를 먼저 확인하세요.
- 브라우저별 세부 동작과 호환성은 약간씩 다를 수 있습니다.

## 테스트 팁
```rust
use bunner_shield_rs::prelude::*;

let shield = Shield::new()
		.coop(CoopOptions::new().policy(CoopPolicy::SameOriginAllowPopups))?;
let result = shield.secure(headers)?;
assert_eq!(
		result.get("Cross-Origin-Opener-Policy").map(String::as_str),
		Some("same-origin-allow-popups")
);
```

## FAQ
- Q. COOP만 설정하면 충분한가요?
	- A. 아닙니다. 교차 출처 격리에는 COEP도 필요합니다.
- Q. `same-origin`과 `same-origin-allow-popups` 차이는 무엇인가요?
	- A. 둘 다 격리를 제공하지만, 후자는 팝업과의 호환성을 위해 일부 상호작용을 허용해 보안 경계가 완화됩니다.
- Q. 점진 도입 방법은?
	- A. `report_only()`로 시작해 위반·영향을 관찰한 뒤 강제 모드로 전환하세요.