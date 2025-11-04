# COEP (Cross-Origin-Embedder-Policy)

교차 출처 리소스를 임베드할 때의 격리 정책을 정의하는 응답 헤더입니다. `COEP`는 페이지가 임베드하는 모든 교차 출처 리소스가 CORS 또는 CORP를 통해 명시적으로 허용되도록 강제하거나, 자격 증명 없이 가져오도록 강제하여 교차 출처 격리(cross-origin isolation) 달성을 돕습니다.

관련 헤더 키:
- 강제: `Cross-Origin-Embedder-Policy`
- 리포트 전용: `Cross-Origin-Embedder-Policy-Report-Only`

## 옵션 요약
- 지원 정책: `require-corp`, `credentialless`
- 모드: 강제(enforce, 기본), 리포트 전용(report-only)
- 표준 직렬화와 헤더 키 전환(강제/리포트 전용) 자동 처리

## 언제 사용하나요?
- SharedArrayBuffer, Atomics 등 강력한 기능 사용을 위한 교차 출처 격리를 달성하려는 경우
- 제3자 리소스를 임베드하지만, CORS 헤더를 제어할 수 없거나 자격 증명 없이 로드하도록 강제하려는 경우
- 임베드된 리소스의 출처·정책 위반을 관찰하고 점진적으로 강제하고 싶은 경우(리포트 전용)

## 동작 방식
COEP는 페이지가 임베드하는 모든 교차 출처 리소스에 대해 다음 중 하나를 강제합니다.
- require-corp: 리소스가 CORS를 통해 허용되거나, 응답에 `Cross-Origin-Resource-Policy`(CORP) 헤더가 있어야 로드됩니다.
- credentialless: 교차 출처 요청에서 자격 증명(쿠키, 인증 헤더 등)을 제거하여 리소스가 비인증 컨텍스트로 로드되도록 합니다.

일반적으로 완전한 교차 출처 격리를 위해서는 COEP와 함께 COOP(보통 `same-origin`)을 설정해야 합니다. 또한 임베드되는 리소스(정적 파일 서버, CDN, 제3자 API 등)에는 CORS 또는 CORP가 적절히 설정되어야 합니다.

## 옵션(정책) 상세
- require-corp (기본): 가장 엄격하고 예측 가능성이 높습니다. 리소스가 명시적으로 허용되지 않으면 차단되므로, 자체 자산과 제3자 리소스 모두에 CORS/CORP 구성이 필요합니다.
- credentialless: 자격 증명을 제거해 로드합니다. 제3자 리소스에 CORS/CORP를 붙이기 어렵거나, 인증이 필요 없는 리소스를 주로 사용하는 경우에 유용합니다. 단, 인증이 필요한 리소스는 기대대로 동작하지 않을 수 있습니다.

## 모드
- 강제(Enforce, 기본): `Cross-Origin-Embedder-Policy`에 정책 값을 설정해 즉시 강제합니다.
- 리포트 전용(Report-Only): `Cross-Origin-Embedder-Policy-Report-Only`를 사용해 위반을 관찰합니다. 본 라이브러리는 리포트 전용을 설정할 때 강제 헤더를 자동으로 제거하여 중복 적용을 방지합니다.

## 권장 설정 가이드
- 목표가 교차 출처 격리 달성인 경우: COEP=`require-corp` + COOP=`same-origin` 조합을 권장합니다. 리소스 제공 측(CDN/정적 서버)에 CORS 또는 CORP를 설정하세요.
- 제3자 리소스가 많고 CORS 제어가 어려운 경우: COEP=`credentialless`를 고려하십시오. 인증 의존 리소스는 동작이 달라질 수 있으므로 주의하세요.
- 도입 단계: 먼저 리포트 전용으로 배포해 위반을 관찰하고, 점차 강제 모드로 전환하세요.

## 라이브러리 통합
이 라이브러리는 COEP를 독립 기능으로 제공하며, Builder로 손쉽게 조합할 수 있습니다. 검증은 간단하며, 정책 문자열 파서도 지원합니다.

### 빠른 시작
```rust
use bunner_shield_rs::prelude::*;

// 엄격한 격리를 위한 권장값: require-corp (기본)
let coep = CoepOptions::new();
let shield = Shield::builder().coep(coep).build();

// 또는 명시적으로 지정
let coep = CoepOptions::new().policy(CoepPolicy::RequireCorp);

// 문자열로부터 생성
let coep = CoepOptions::from_policy_str("require-corp")?;
```

### Credentialless 사용 예
```rust
use bunner_shield_rs::prelude::*;

let coep = CoepOptions::new().policy(CoepPolicy::Credentialless);
let shield = Shield::new().coep(coep)?;
let res = shield.secure(headers)?;
assert_eq!(
		res.get("Cross-Origin-Embedder-Policy").map(String::as_str),
		Some("credentialless")
);
```

### Report-Only로 시작하기
```rust
use bunner_shield_rs::prelude::*;

let coep_ro = CoepOptions::new().report_only();
let shield = Shield::builder().coep(coep_ro).build();
let res = shield.secure(headers)?;
// 강제 키 대신 Report-Only 키가 설정됩니다.
assert!(res.get("Cross-Origin-Embedder-Policy").is_none());
assert!(res
		.get("Cross-Origin-Embedder-Policy-Report-Only")
		.is_some());
```

## API 참고
- CoepOptions::new(), .policy(CoepPolicy), .policy_from_str(&str) → Result, CoepOptions::from_policy_str(&str) → Result
- .report_only()로 모드 전환 (기본은 Enforce)
- Shield 통합: `Shield::builder().coep(options)` 또는 즉시 검증 경로 `Shield::new().coep(options)?`

## 주의 사항 및 한계
- COEP만으로는 교차 출처 격리가 완성되지 않습니다. COOP(`same-origin`)과 함께 사용하세요.
- require-corp 선택 시, 임베드되는 모든 교차 출처 리소스는 CORS 또는 CORP로 명시 허용되어야 합니다. 설정 누락 시 로드가 차단됩니다.
- credentialless는 자격 증명이 제거되므로, 인증이 필요한 리소스에는 부적합할 수 있습니다.
- 브라우저별 지원과 세부 동작은 차이가 있을 수 있습니다. 점진적 도입을 위해 Report-Only로 먼저 배포하는 것을 권장합니다.

## 테스트 팁
```rust
use bunner_shield_rs::prelude::*;

let shield = Shield::new()
		.coep(CoepOptions::new().policy(CoepPolicy::Credentialless))?;
let result = shield.secure(headers)?;
assert_eq!(
		result.get("Cross-Origin-Embedder-Policy").map(String::as_str),
		Some("credentialless")
);
```

## FAQ
- Q. COEP만 설정하면 교차 출처 격리가 달성되나요?
	- A. 아닙니다. 일반적으로 COOP(`same-origin`)도 필요합니다. 리소스 측 CORS/CORP 설정도 필수입니다.
- Q. require-corp와 credentialless의 차이는 무엇인가요?
	- A. require-corp는 CORS/CORP로 명시 허용된 리소스만 허용합니다. credentialless는 자격 증명을 제거하여 비인증 상태로 로드합니다.
- Q. 점진 도입 방법이 있나요?
	- A. `report_only()`로 리포트 전용부터 시작해 위반을 관찰한 뒤 강제 모드로 전환하세요.