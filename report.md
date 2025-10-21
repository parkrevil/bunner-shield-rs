# bunner-shield-rs: 엔지니어링 액션 아이템 보고서 (2025-10-21)

아래 항목은 “코드 변경으로 바로 작업 가능한” 내용만 남긴 리스트입니다. 문서화/프리셋/템플릿 제안은 모두 제외했습니다. 대상은 공통 인프라 + 15개 Feature 모듈입니다.

## 공통 인프라
- 에러 타입/메시지 통일화
	- 작업: 각 모듈 `*_error.rs` 또는 `options.rs`의 `Error` 파생 thiserror 메시지를 소문자 시작·마침표 없음 규칙으로 정리.
	- 수용 기준: 전 테스트 통과, clippy -D warnings 통과, 에러 스냅샷 존재 시 갱신.

- unsafe 금지 선언 추가
	- 작업: `src/lib.rs` 상단에 `#![forbid(unsafe_code)]` 선언 추가. 워크스페이스 전반에 unsafe 사용이 없음을 보장.
	- 수용 기준: Build/Lint/Tests 모두 PASS.

- Rust 버전 고정 선언
	- 작업: `Cargo.toml`에 `rust-version = "<MSRV>"` 명시(현재 CI/개발 환경 기준). Semver 호환 범위에서 유지.
	- 수용 기준: cargo metadata/빌드 정상 동작.

- 퍼징(fuzzing) 추가
	- 작업: `cargo-fuzz`로 파서/정규화 경로 fuzz 타겟 추가.
		- 타겟: `csp`, `permissions_policy`, `same_site`, `clear_site_data`, `referrer_policy` 각 `Options::from_str`/정규화 유틸.
	- 수용 기준: fuzz 타겟 빌드 가능, smoke run 수행(충돌/UB 없음), 최소 시드 코퍼스 포함.

- 속성 테스트(property-based) 확대
	- 작업: proptest로 다음 속성 보장:
		- 병합 연산: 결합법칙/교환법칙/멱등성(CSP source 집합, Permissions-Policy allowlist, Clear-Site-Data 섹션 집합).
		- 정규화/직렬화: 안정 직렬화의 멱등성(serialize ∘ parse ∘ serialize 동일), 중복 제거 후 순서 안정.
	- 수용 기준: 신규 속성 테스트 추가, 전체 테스트 PASS 유지.

- 공개 타입의 Send/Sync 보증
	- 작업: 중요 공개 타입(옵션, 실행자)이 `Send + Sync`를 만족하는지 compile-time 어서션 테스트 추가.
	- 수용 기준: 빌드 PASS, 어서션 실패 없음.

- HTTP/2·HTTP/3 헤더 호환성 검증
	- 작업: 모든 헤더 키/값이 HTTP/2·HTTP/3 명세(소문자, 금지 문자 없음, pseudo-header 충돌 없음)를 만족하는지 컴파일/런타임 검증 추가.
	- 수용 기준: 신규 테스트 PASS, HTTP/2·HTTP/3 클라이언트 통합 테스트(선택).

- 비동기 런타임 호환성 보장
	- 작업: 공개 타입/API가 tokio/async-std/smol 등 주요 런타임에서 안전하게 동작하는지 Send+Sync+!RefCell 등 제약 검증. 런타임 종속성 없이 유지.
	- 수용 기준: 컴파일 타임 어서션 PASS, 다중 런타임 예제(선택) 빌드 성공.

- 미들웨어 통합 예제 패턴
	- 작업: `examples/` 디렉터리에 주요 웹 프레임워크(axum, actix-web, warp, rocket) 연동 예제 추가.
		- 각 예제: Shield 파이프라인 적용, 런타임 nonce 주입, 에러 핸들링 시연.
	- 수용 기준: 모든 예제 빌드/실행 가능, README에 프레임워크별 사용법 링크.

- 보안 정책 프리셋(코드 제공, 문서 아님)
	- 작업: `src/presets.rs` 모듈 추가, 일반 사용 사례별(strict/balanced/permissive) Shield 구성 프리셋 제공.
		- 각 프리셋: CSP/HSTS/Permissions-Policy/Referrer-Policy/SameSite 등 조합, 빌더 체이닝으로 구성.
	- 수용 기준: 프리셋 API 빌드 PASS, 테스트에서 프리셋 적용 시 예상 헤더 출력 검증.

## CSP
- 위험 스킴 경고 강화 로직 세분화
	- 작업: `src/csp/options/config/core.rs::emit_risky_scheme_warnings`에서 `navigate-to`/`frame-ancestors`의 `data:` 사용은 Critical, 기타 일부는 Warning/Info로 세분화 테이블 조정(현재도 있으나 경계값 재조정).
	- 수용 기준: 기존 경고 테스트 유지 + 신규 케이스 추가, 헤더 직렬화 결과 불변.

- Strict-Dynamic 충돌 탐지 보강
	- 작업: `strict_dynamic_has_host_sources` 검사를 스크립트 패밀리 전체에 대해 교차 점검하도록 보완.
	- 수용 기준: 기존 테스트 유지 + host source 혼합 케이스 추가.

- 대형 정책 직렬화 벤치 추가(선택)
	- 작업: `benches/bunner_shield_rs.rs`에 수천 토큰 규모 정책 직렬화 벤치 케이스 추가.
	- 수용 기준: 빌드/벤치 실행 가능, 기능 회귀 없음.

- 퍼징 타겟 추가
	- 작업: `Options::from_str`(있는 경우) 및 directive/token 정규화 루틴 대상 fuzz 타겟 구현.
	- 수용 기준: fuzz smoke run 충돌 없음.

- 속성 테스트(병합/직렬화 불변식)
	- 작업: 병합 연산의 결합/교환/멱등, 직렬화 멱등(파싱→직렬화 불변), 토큰 중복 제거 안정성 속성 테스트 추가.
	- 수용 기준: 신규 테스트 PASS.

## COOP
- 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 공백/대소문 혼합 입력 정규화 경로를 fuzz/proptest로 커버.
	- 수용 기준: 신규 테스트 PASS, fuzz smoke run 충돌 없음.
- 파서 경계값 검사 강화
	- 작업: 옵션 파서에서 공백/대소문 혼합 입력의 정규화 경로에 추가 trim/normalize.
	- 수용 기준: 기존 테스트 유지 + 경계 케이스 추가.

## COEP
- 퍼징/속성 테스트 적용(공통 규약)
	- 작업: credentialless/require-corp 파서에 fuzz/proptest 추가.
	- 수용 기준: 신규 테스트 PASS.
- 입력 정규화 강화
	- 작업: credentialless/require-corp 외 임의 공백·혼용 입력에 대한 엄격 트리밍 이미 존재. 혼합 대소문 경로 재검증 및 테스트 추가.
	- 수용 기준: 기존 테스트 유지 + 신규 케이스 추가.

## CORP
- 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 정책 파서·직렬화 경로 속성/퍼징 추가.
	- 수용 기준: 신규 테스트 PASS.
## Clear-Site-Data
- [ ] 입력 정규화/에러 메시지 통일
	- 작업: 알려지지 않은 섹션 값에 대해 일관된 오류 메시지로 통일하고, 공백만 있는 세그먼트는 조기 거부(현재 일부 검증 존재, 메시지 규칙 일치화).
	- 수용 기준: 기존 테스트 유지 + 에러 메시지 스냅샷 정렬.

- [ ] 중복/순서 처리 보강(무변화 보장)
	- 작업: 직렬화 전 내부에서 중복 제거 후 현재의 안정 순서 정책을 유지(현 테스트와 결과 동일). 구현 경로의 조기 반환 등 미세 최적화 검토.
	- 수용 기준: 헤더 문자열 스냅샷 불변, 성능 회귀 없음.

- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 섹션 토큰 파서 및 조합 직렬화 경로에 fuzz/proptest 추가(집합 연산 속성 보장).
	- 수용 기준: 신규 테스트 PASS.
- [ ] 옵션 병합 시 토큰 중복 제거 보강
	- 작업: 빌더 merge 경로에서 동일 정책 재적용 시 중복 제거 로직 재사용.
	- 수용 기준: 기존 테스트 유지 + 중복 입력 케이스 추가.

## Permissions-Policy
- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 피처명·allowlist 파서/정규화 경로에 fuzz/proptest 추가(중복 제거 안정성 속성 포함).
	- 수용 기준: 신규 테스트 PASS.
- [ ] 피처명 정규식 검증 추가
	- 작업: `^[a-z][a-z0-9-]*$` 패턴으로 강화. 현재 트리밍/빈 값 거부 외에 추가 검증 분기만 추가.
	- 수용 기준: 기존 테스트 유지 + 잘못된 피처명 케이스 추가.

- [ ] allowlist 토큰 중복 제거/정렬 안정화
	- 작업: 현재는 입력 순서 보존 + 중복 제거. 내부 표현에서 안정 정렬 후 직렬화는 기존 순서 유지 여부 검토(기존 스냅샷 호환 전제).
	- 수용 기준: 스냅샷 유지, 신규 중복 케이스 통과.

## Referrer-Policy
- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 값 파서 케이스에 fuzz/proptest 추가.
	- 수용 기준: 신규 테스트 PASS.
- [ ] 파서 엄격 모드 옵션화 대신 기본 동작으로 동작하도록 작업
	- 작업: 공백/대소문 변형 허용하되, 알 수 없는 값은 명시 오류. 현재도 오류이지만 메시지 통일화.
	- 수용 기준: 기존 테스트 유지 + 에러 메시지 스냅샷 정렬.

## HSTS
- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 옵션 조합 검증 경로에 proptest 추가(불변식: preload→includeSubDomains∧max-age≥1y).
	- 수용 기준: 신규 테스트 PASS.
- [ ] preload 조합 검증 강화
	- 작업: `preload` true이면 `includeSubDomains` 필수 및 `max-age>=31536000` 강제는 이미 검증됨. 에러 메시지 규칙 정리만 수행.
	- 수용 기준: 기존 테스트 유지.

## SameSite Cookie
- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: 쿠키 문자열 정규화/적용 경로에 fuzz/proptest 추가(멱등·비파괴 속성 보장).
	- 수용 기준: 신규 테스트 PASS.
- [ ] 파서 튼튼화
	- 작업: 다중 세미콜론/공백 비정상 입력에 대한 내재 정규화 경로 보강(기능 변화 없음).
	- 수용 기준: 기존 테스트 유지 + 경계 케이스 추가.

## CSRF Token
- [ ] 퍼징/속성 테스트 적용(공통 규약)
	- 작업: Base64url 디코딩/서명 검증 경로에 fuzz/proptest 추가(거부-수용 경계값 검증).
	- 수용 기준: 신규 테스트 PASS.
- [ ] 키 로테이션 경로 경계값 보강
	- 작업: 다중 키 검증 경로에서 비정상 base64url 입력 처리 시 조기 실패 지점 명확화(현재도 실패). 에러 메시지 정렬만 수행.
	- 수용 기준: 기존 테스트 유지.

## X-Frame-Options
- [ ] 중복값/케이싱 보정
	- 작업: 기존 헤더 존재·혼합 케이스에서 캐시된 값 재사용 및 비정상 키 제거 확인 테스트 강화.
	- 수용 기준: 기존 기능 유지 + 테스트 확증.

## 웹 서버 통합 보강
- 에러 처리 전략 통일
	- 작업: 모든 Feature의 `validate_options`/`execute` 실패 시 일관된 에러 타입 반환. `Shield::secure` 실패 시 부분 적용 여부 정책 명확화(현재: 첫 실패 시 중단).
	- 수용 기준: 에러 핸들링 테스트 추가, 문서/주석에 정책 명시.

- 헤더 우선순위/충돌 해결 정책 문서화(코드 주석)
	- 작업: 동일 키에 여러 Feature가 영향(예: X-Frame-Options vs CSP frame-ancestors)을 미칠 때 우선순위 규칙을 코드 주석 또는 `constants.rs`에 명시.
	- 수용 기준: 주석 추가, 충돌 케이스 통합 테스트 추가.

- 성능 프로파일링 벤치 확대
	- 작업: `benches/`에 전체 Shield 파이프라인(15 feature 동시 적용) 처리 시간·메모리 벤치 추가. 대규모 헤더 맵(수천 항목) 처리 벤치.
	- 수용 기준: 벤치 실행 가능, 회귀 탐지 기준선 설정.

- Observability 후크(선택, feature flag)
	- 작업: Shield 파이프라인 실행 시 메트릭/로깅 콜백 제공(선택, feature="observability").
		- 예: 각 Feature 실행 시간, 경고 발생 횟수, 헤더 변경 로그.
	- 수용 기준: feature flag 활성화 시 빌드 PASS, 콜백 호출 테스트 PASS.

- 배포 검증 체크리스트(코드 기반)
	- 작업: `src/validation.rs` 모듈 추가, 프로덕션 배포 전 Shield 구성 자동 검증 유틸.
		- 검증 항목: HSTS preload 조건 충족, CSP unsafe 사용 경고, SameSite=None+Secure 조합 등.
	- 수용 기준: 검증 API 빌드 PASS, 부적합 구성 탐지 테스트 PASS.

---

품질 게이트
- Build/Lint/Tests: 모두 PASS 유지가 조건. 공개 API/헤더 직렬화 결과 불변(에러 메시지 텍스트는 통일 규칙에 맞게 변경 가능).
- CI 추가 조건(선택 포함)
	- Coverage ≥ 목표치, cargo-deny/audit/pubic-api/miri 단계 녹색, fuzz smoke run 무충돌.
