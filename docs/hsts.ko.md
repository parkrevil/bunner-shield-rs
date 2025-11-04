# HSTS (Strict-Transport-Security)

브라우저에 “해당 도메인은 HTTPS만 사용”을 선언합니다. `Strict-Transport-Security` 헤더로 전달되며, 중간자 공격을 줄이고 다운그레이드(HTTP) 접속을 방지합니다.

기본값과 특징
- 기본 max-age: 31536000초(1년)
- includeSubDomains: 기본 비활성화
- preload: 기본 비활성화(조건 충족 시에만 사용)
- HTTPS 응답에만 설정해야 하며, HTTP에서는 절대 설정하지 않습니다.

## 옵션
- `max_age(u64)`: 정책 유효 시간(초). 권장: 최소 6개월, 보통 1년 이상.
- `include_subdomains()`: 모든 서브도메인에도 강제 HTTPS 적용.
- `preload()`: 브라우저 HSTS preload 리스트 등재 의사 표시. 다음을 모두 만족해야 합니다:
	- includeSubDomains 활성화
	- max-age >= 31536000
	- 도메인 소유 및 지속적 HTTPS 운영에 자신 있는 경우만 권장

헤더 예시
- 기본 직렬화: `max-age=31536000; includeSubDomains; preload` 형태로 세미콜론 구분

## 권장 설정
- 초기에: `max-age`를 점진적으로 늘려 배포(예: 1주 → 1달 → 6개월 → 1년)
- 성숙 단계: `includeSubDomains` 활성화 후 충분히 안정화되면 `preload` 검토
- 프리로드: 운영/서브도메인 전역 HTTPS가 확실하고 장기 유지가 가능한지 확인 후 설정

## 사용 예시
```rust
use bunner_shield_rs::prelude::*;

// 안정적인 서비스에 권장되는 예
let hsts = HstsOptions::new()
		.include_subdomains()
		.preload();

let shield = Shield::builder().hsts(hsts).build();
```

## 주의 사항
- HTTP 응답에 HSTS를 설정하면 무의미하며 보안상 혼란을 줄 수 있습니다. 반드시 HTTPS에서만 설정하세요.
- 프리로드는 되돌리기 어렵습니다. 운영 전체가 HTTPS로 일관되고, 서브도메인까지 커버할 수 있어야 합니다.
- 오래된 브라우저/클라이언트 일부는 HSTS 신호를 따르지 않을 수 있습니다.