# CORP (Cross-Origin-Resource-Policy)

현재 출처의 리소스를 다른 출처가 어떻게 사용할 수 있는지 제어하는 응답 헤더입니다. CORP는 교차 출처로부터의 임베드·가져오기를 정책적으로 제한해, 의도치 않은 재사용과 데이터 누출 가능성을 줄입니다. COEP(require-corp)와 조합하면 임베드되는 리소스가 명시적으로 허용되었을 때만 로드되도록 강제할 수 있습니다.

관련 헤더 키:
- `Cross-Origin-Resource-Policy`

## 옵션 요약
- 지원 정책: `same-origin`(기본), `same-site`, `cross-origin`
- 직렬화는 표준 값 그대로 적용되며, 중복 제거·안정적 순서를 보장합니다.

## 언제 사용하나요?
- 정적 자산(HTML, JS, CSS, 이미지, 폰트 등)이나 API 응답을 제3자 사이트가 임의로 임베드·재사용하는 것을 제한하고 싶을 때
- COEP(require-corp) 페이지에서 로드되는 리소스로서, 명시 허용되지 않은 교차 출처 접근을 차단하고 싶을 때
- CDN/정적 서버에서 외부 오용을 방지하거나, 민감 리소스를 엄격히 동일 출처로만 제공하고 싶을 때

## 동작 방식
리소스 응답에 CORP를 설정하면, 브라우저는 교차 출처 접근을 다음과 같이 제한합니다.
- `same-origin`: 동일 출처에서만 해당 리소스를 사용할 수 있습니다. 가장 엄격합니다.
- `same-site`: 동일 사이트(예: `a.example.com` ↔ `b.example.com`)에서 사용할 수 있습니다.
- `cross-origin`: 교차 출처에서도 사용할 수 있습니다. 공개적으로 임베드 가능한 리소스에 적합합니다.

COEP가 `require-corp`인 페이지에서는, 리소스를 로드하려면 해당 리소스 응답이 CORP로 명시 허용되었거나 CORS로 허용되어 있어야 합니다. 따라서 COEP를 사용하는 애플리케이션은 자체 리소스 서버/정적 서버/CDN에 CORP 또는 CORS를 적절히 배치해야 합니다.

## 권장 설정 가이드
- 기본 보안(내부 자산): `same-origin` 권장 — 내부 리소스를 외부 출처에서 임의로 사용할 수 없게 합니다.
- 멀티 서브도메인 환경: 동일 사이트 간 공유가 필요한 자산에는 `same-site` 고려
- 공개 자산(CDN 공개 이미지/폰트 등): `cross-origin` 설정 — 임베드 허용 목적의 리소스에만 사용하세요.
- COEP=require-corp 페이지와의 조합: 필요한 리소스들만 `same-site` 또는 `cross-origin`으로 완화하고, 나머지는 `same-origin` 유지

## 라이브러리 통합
이 라이브러리는 CORP를 독립 기능으로 제공하며, Builder 또는 즉시 추가 경로로 손쉽게 구성할 수 있습니다. 문자열 파서를 통해 정책 값을 안전하게 파싱할 수 있습니다.

### 빠른 시작
```rust
use bunner_shield_rs::prelude::*;

// 기본(권장) 값: same-origin
let corp = CorpOptions::new();
let shield = Shield::builder().corp(corp).build();
```

### 정책 명시 및 문자열 파싱
```rust
use bunner_shield_rs::prelude::*;

let corp = CorpOptions::new().policy(CorpPolicy::SameSite);
let corp_from_str = CorpOptions::from_policy_str("cross-origin")?;
```

## API 참고
- CorpOptions::new(), .policy(CorpPolicy), .policy_from_str(&str) → Result, CorpOptions::from_policy_str(&str) → Result
- Shield 통합: `Shield::builder().corp(options)` 또는 즉시 검증 경로 `Shield::new().corp(options)?`

## 주의 사항 및 한계
- 과도하게 엄격한 설정은 합법적인 교차 출처 사용(예: 파트너 도메인, 동일 사이트 내 서브도메인)을 방해할 수 있습니다. 필요한 최소 범위로만 완화하세요.
- COEP=require-corp 페이지에서 CORP가 누락되면 리소스가 차단될 수 있습니다. 필요한 리소스에는 CORP 또는 CORS를 명시하세요.
- 브라우저별 세부 동작·캐싱 상호작용은 차이가 있을 수 있습니다. 점진적으로 도입하고 관찰하세요.

## 테스트 팁
```rust
use bunner_shield_rs::prelude::*;

let shield = Shield::new()
		.corp(CorpOptions::new().policy(CorpPolicy::CrossOrigin))?;
let result = shield.secure(headers)?;
assert_eq!(
		result.get("Cross-Origin-Resource-Policy").map(String::as_str),
		Some("cross-origin")
);
```

## FAQ
- Q. COEP가 없더라도 CORP만으로 보호가 되나요?
	- A. CORP만으로도 교차 출처 임베드 제한에 도움이 되지만, COEP=require-corp 페이지와 조합하면 보다 강력하고 예측 가능한 격리를 달성할 수 있습니다.
- Q. 어떤 리소스에 `cross-origin`을 써야 하나요?
	- A. 공개적으로 임베드를 허용하려는 리소스(예: 공개 폰트/아이콘 스프라이트 등)에만 사용하세요. 그렇지 않다면 기본적으로 `same-origin`을 유지하세요.
- Q. 동일 사이트 간 공유가 필요한데 보안도 유지하려면?
	- A. `same-site`를 사용해 서브도메인 간 공유를 허용하면서, 완전한 교차 출처 공개(`cross-origin`)는 피할 수 있습니다.