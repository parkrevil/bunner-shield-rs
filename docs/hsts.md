# HSTS 가이드

HTTP Strict Transport Security(HSTS)는 브라우저가 지정된 기간 동안 해당 도메인(및 선택적으로 모든 서브도메인)에 대해 오직 HTTPS만 사용하도록 강제합니다. 잘못 구성하면 복구가 어려울 수 있으므로 점진적 롤아웃과 사전 점검을 권장합니다.

## TL;DR 권장 설정

- 프로덕션: `max-age=63072000`(약 2년) + `includeSubDomains` + (충분히 검증 후) `preload`
- 프리로드 제출 전 체크리스트
  - 모든 서브도메인이 HTTPS로 제공되는지
  - HSTS 헤더가 루트 및 서브도메인에 일관되게 적용되는지
  - 서브도메인 중 폐기/이관 예정인 것이 없는지

프리로드 리스트 등록에는 최소 1년의 `max-age`가 요구되지만, 장기적인 보안을 위해 2년(63,072,000초)을 권장합니다. 2년은 장기 캐시/클라이언트 오프라인 기간 등을 고려한 보수적 기간입니다.

## bunner-shield-rs에서의 사용법

기본값

- `HstsOptions::default()`는 `max-age=31536000`(1년), `include_subdomains=false`, `preload=false` 입니다.
- 프리로드 조건(Chrome 등): `includeSubDomains`가 필요하고, `max-age >= 31536000` 이어야 합니다.

예시

```rust
use bunner_shield_rs::hsts::HstsOptions;

// 1) 점진적 롤아웃(서브도메인 적용 전)
let options = HstsOptions::new()
    .max_age(86_400); // 1일 - 모니터링과 롤백 경로 확보

// 2) 서브도메인 전환 준비 후 기간 확대
let options = HstsOptions::new()
    .max_age(2_592_000); // 30일

// 3) 전체 HTTPS 전환 완료 후 서브도메인 포함 + 장기 기간
let options = HstsOptions::new()
    .include_subdomains()
    .max_age(63_072_000); // 2년 권장

// 4) 충분한 검증 이후 프리로드 플래그 추가(조건 충족 확인 필수)
let options = HstsOptions::new()
    .include_subdomains()
    .max_age(63_072_000)
    .preload();

// 비활성화(중단/롤백 시)
let disable = HstsOptions::new().max_age(0);
```

해더 출력 값은 `max-age=...; includeSubDomains; preload` 형태로 직렬화됩니다(플래그가 활성화된 경우에만 포함).

## 권장 롤아웃 단계

1) 탐색 단계
- `max-age=86400`(1일)부터 시작하여 모니터링합니다.
- 혼합 콘텐츠, 리디렉션 루프, 캐시 키 이슈 등을 점검합니다.

2) 기간 확대
- 30일 등으로 점진 확대.
- 서브도메인 HTTPS 전환 계획 수립/완료.

3) 서브도메인 포함
- `includeSubDomains`를 켠 뒤 전 영역 HTTPS를 재검증합니다.
- 여전히 문제가 없다면 장기 기간(2년)을 설정합니다.

4) 프리로드 준비 및 제출
- `preload` 플래그 추가, 최소 1년 이상 `max-age` 확인(2년 권장).
- https://hstspreload.org 에 제출.

## 주의사항 및 복구

- 잘못된 설정은 접속 불가로 이어질 수 있으며, 특히 프리로드 후에는 빠른 롤백이 어렵습니다.
- 내부 도메인/마이크로서비스/정적 서브도메인까지 HTTPS 통일이 필요합니다.
- 비상시에는 `max-age=0`로 비활성화가 가능하지만, 프리로드는 브라우저 목록 갱신 주기가 있어 즉시 해제되지 않습니다(제거 요청 필요).

## 검증 포인트 체크리스트

- [ ] 모든 HTTP 엔드포인트가 301/308로 HTTPS로 영구 리디렉션되는가?
- [ ] 정적 리소스/CNAME/서브도메인 전부 TLS로 제공되는가?
- [ ] 캐시/프록시/로드밸런서 층에서 헤더가 누락되거나 변조되지 않는가?
- [ ] Third-party 서브도메인 위임 구성이 없는가(또는 HSTS 영향 검토 완료)?

