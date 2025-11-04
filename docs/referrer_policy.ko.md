# Referrer-Policy

요청에 첨부되는 Referer 정보의 범위를 제어합니다. 헤더: `Referrer-Policy`.

## 옵션 요약
- 주요 값:
	- `no-referrer`
	- `no-referrer-when-downgrade`
	- `same-origin`
	- `origin`
	- `strict-origin`
	- `origin-when-cross-origin`
	- `strict-origin-when-cross-origin`(기본/권장)
	- `unsafe-url`
- 다중 값 지원(쉼표 구분). 브라우저는 지원되는 첫 값을 사용
- 기본값: `strict-origin-when-cross-origin`

## 예시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::referrer_policy::ReferrerPolicyValue as V;

// 단일 값 지정
let rp = ReferrerPolicyOptions::new().policy(V::StrictOriginWhenCrossOrigin);
let shield = Shield::builder().referrer_policy(rp).build();
```

### 다중 값 구성
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::referrer_policy::ReferrerPolicyValue as V;

let rp = ReferrerPolicyOptions::new()
		.policies([
				V::StrictOriginWhenCrossOrigin,
				V::NoReferrer, // 구형 브라우저 호환용 보조 값
		]);

let shield = Shield::builder().referrer_policy(rp).build();
// 헤더 예: "strict-origin-when-cross-origin, no-referrer"
```

## 권장 사항
- 대부분의 서비스에 `strict-origin-when-cross-origin`가 안전성과 호환성 균형이 좋습니다.
- 매우 민감한 개인정보를 다루는 페이지에서만 `no-referrer`를 고려하세요.