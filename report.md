# bunner-shield-rs 보안 라이브러리 개선 사항

> **분석 일자**: 2025-10-31  
> **상태**: 프로덕션 배포 불가 - 치명적 결함 다수 발견

이 문서는 `bunner-shield-rs` 라이브러리의 코드베이스 전체를 분석하여 발견된 개선 사항을 카테고리별로 정리한 것입니다.

---

## 📋 목차

1. [치명적 문제 (즉시 해결 필수)](#1-치명적-문제-즉시-해결-필수)
2. [표준 준수 및 기능 완성](#2-표준-준수-및-기능-완성)
3. [보안 설계 및 아키텍처](#3-보안-설계-및-아키텍처)
4. [API 설계 및 DX 개선](#4-api-설계-및-dx-개선)
5. [문서화 및 배포](#5-문서화-및-배포)
6. [성능 및 최적화](#6-성능-및-최적화)
7. [테스트 및 품질 보증](#7-테스트-및-품질-보증)

---

## 1. 치명적 문제 (즉시 해결 필수)

### 1.1. 빌드 불가능한 Rust 에디션 설정
- **파일**: `Cargo.toml`
- **문제**: `edition = "2024"` 설정으로 빌드 실패
- **영향**: 프로젝트 컴파일 불가
- **TODO**:
  - [ ] `edition = "2021"`로 수정
  - [ ] 빌드 성공 확인

### 1.2. CSRF 토큰 검증 로직 완전 누락
- **파일**: `src/csrf/executor.rs`
- **문제**: 토큰 발급만 수행하고 검증은 전혀 하지 않음
- **영향**: CSRF 공격 방어 불가능 (보안 기능 무효)
- **TODO**:
  - [ ] `Csrf` executor에 토큰 검증 로직 추가
  - [ ] POST/PUT/DELETE 요청 시 `X-CSRF-Token` 헤더 검증 구현
  - [ ] 요청 vs 응답 컨텍스트 분리 (요청 검증 전용 인터페이스 설계)
  - [ ] `HmacCsrfService::verify` 기본 동작에 만료 시간 검증 추가
  - [ ] `CsrfReplayStore` 기본 구현체 제공 (메모리/Redis 등)
  - [ ] 프레임워크별 통합 가이드 작성 (Axum, Actix-web 등)

### 1.3. Set-Cookie 헤더 병합으로 인한 HTTP 명세 위반
- **파일**: `src/normalized_headers.rs`, `tests/integration.rs`
- **문제**: 여러 `Set-Cookie` 값을 `\n`으로 연결하여 단일 문자열로 반환
- **영향**: RFC 6265/7230 위반, 헤더 인젝션/응답 스플리팅 취약점 가능
- **TODO**:
  - [ ] `NormalizedHeaders::into_result()` API 재설계
  - [ ] 반환 타입을 `HashMap<String, Vec<String>>`로 변경 검토
  - [ ] 또는 `Set-Cookie` 전용 메서드 추가 (`get_cookies() -> Vec<String>`)
  - [ ] 통합 테스트 수정 (개행 기반 검증 제거)
  - [ ] 프레임워크 어댑터에서 다중 헤더 변환 가이드 제공

### 1.4. 요청/응답 헤더 혼합으로 인한 보안 위험
- **파일**: `src/shield.rs`, `tests/fetch_metadata.rs`
- **문제**: 단일 `HashMap`에 요청과 응답 헤더가 섞여 처리됨
- **영향**: 요청 헤더가 응답에 반사되어 정보 누출/캐시 오염 가능
- **TODO**:
  - [ ] 요청 검증 전용 인터페이스 분리 (`RequestInspector` 트레이트)
  - [ ] 응답 헤더 설정 전용 인터페이스 분리 (`ResponseSecurer` 트레이트)
  - [ ] `Shield::secure()` 사용 시 주의사항 문서화
  - [ ] 요청 헤더 필터링 헬퍼 함수 제공

---

## 2. 표준 준수 및 기능 완성

### 2.1. CSP (Content Security Policy)

#### 2.1.1. `child-src` 지시어 누락
- **파일**: `src/csp/options/types.rs`
- **문제**: `frame-src`와 `worker-src`의 fallback 지시어 미지원
- **표준**: MDN CSP 명세에 포함
- **TODO**:
  - [ ] `CspDirective` enum에 `ChildSrc` 추가
  - [ ] 직렬화 로직에 `"child-src"` 매핑 추가
  - [ ] fallback 동작 검증 테스트 작성

#### 2.1.2. `report-uri` 지시어 누락
- **문제**: deprecated이지만 구형 브라우저 호환성을 위해 필요
- **TODO**:
  - [ ] `CspDirective` enum에 `ReportUri` 추가
  - [ ] `report-to`와 함께 사용하는 패턴 문서화
  - [ ] deprecated 경고 추가

#### 2.1.3. `block-all-mixed-content` deprecated 표시 부재
- **문제**: deprecated 사실이 코드/문서에 명시되지 않음
- **TODO**:
  - [ ] Rustdoc에 `#[deprecated]` 속성 추가
  - [ ] `upgrade-insecure-requests` 권장 안내 추가

### 2.2. Referrer-Policy

#### 2.2.1. 다중 정책 (Fallback) 미지원
- **파일**: `src/referrer_policy/options.rs`
- **문제**: 쉼표로 구분된 여러 정책 설정 불가
- **표준**: MDN에서 브라우저 호환성을 위해 권장
- **TODO**:
  - [ ] `ReferrerPolicyOptions`를 `Vec<ReferrerPolicyValue>`로 변경
  - [ ] 직렬화 시 쉼표로 연결
  - [ ] 단일 정책 편의 메서드 유지 (`.policy()`)

### 2.3. Permissions-Policy

#### 2.3.1. Allowlist 직렬화 오류 (큰따옴표 누락)
- **파일**: `src/permissions_policy/options.rs`
- **문제**: Origin에 큰따옴표가 자동 추가되지 않음
- **TODO**:
  - [ ] `PolicyBuilder`에서 `AllowListItem::Origin` 처리 시 자동 인용
  - [ ] 테스트에 명세 준수 검증 추가

#### 2.3.2. `Feature-Policy` fallback의 부정확한 동작
- **파일**: `src/permissions_policy/executor.rs`
- **문제**: Report-Only 모드에서 `Feature-Policy` 값이 부적절함
- **TODO**:
  - [ ] `Feature-Policy`는 Report-Only 개념이 없음을 문서화
  - [ ] fallback 로직 제거 또는 Enforce 모드로만 제한
  - [ ] Chromium 호환성 표 문서 추가

### 2.4. HSTS (HTTP Strict Transport Security)

#### 2.4.1. `preload` 기본값 검증 (문제 없음)
- **파일**: `src/hsts/options.rs`
- **현재 상태**: `PRELOAD_MIN_MAX_AGE = 31_536_000` (1년) - 표준 충족
- **TODO**:
  - [ ] 2년(63,072,000초) 권장 사항을 문서에 추가
  - [ ] 조직 정책에 따라 상향 설정 가이드 제공

---

## 3. 보안 설계 및 아키텍처

### 3.1. CSRF 방어 메커니즘

#### 3.1.1. Origin/Referer 검증의 Host 헤더 의존성
- **파일**: `src/csrf/executor.rs`, `src/csrf/origin.rs`
- **문제**: `Host` 헤더 기반으로 동적 허용 목록 생성 (위조 가능)
- **TODO**:
  - [ ] `CsrfOptions`에 정적 허용 출처 목록 추가 (`allowed_origins: Vec<String>`)
  - [ ] `Host` 헤더 기반 검증 제거
  - [ ] 사용자가 명시적으로 출처 설정하도록 강제

#### 3.1.2. Stateless 토큰의 Nonce 관리 개선
- **파일**: `src/csrf/token.rs`
- **문제**: `AtomicU64` 카운터가 서버 재시작 시 초기화됨
- **TODO**:
  - [ ] 영구 저장소 기반 nonce 생성 옵션 추가
  - [ ] 또는 랜덤 nonce 사용 권장 (카운터 의존성 제거)

#### 3.1.3. 토큰 검증 메서드 개선
- **파일**: `src/csrf/token.rs`
- **문제**: `verify()`가 만료 시간을 무시함
- **TODO**:
  - [ ] 기본 `verify()` 동작을 만료 시간 포함으로 변경
  - [ ] 서명만 검증하는 메서드는 `verify_signature_only()`로 별도 제공
  - [ ] `verify_with_max_age()`의 `now_secs` 매개변수를 내부에서 자동 계산

### 3.2. Fetch Metadata 검증

#### 3.2.1. 웹 프레임워크 통합 가이드 부재
- **파일**: `src/fetch_metadata/executor.rs`
- **문제**: 검증 실패를 HTTP 응답 코드로 변환하는 방법 불명확
- **상태**: 검증 로직 자체는 구현되어 있음 (정정)
- **TODO**:
  - [ ] Axum extractor 예제 작성
  - [ ] Actix-web middleware 예제 작성
  - [ ] 정책 위반 시 403/500 응답 전략 문서화
  - [ ] 로깅/계측(Observability) 통합 가이드 추가

#### 3.2.2. 정책 결정 Hook 제공
- **TODO**:
  - [ ] `on_violation` 콜백 옵션 추가
  - [ ] 거부 응답 커스터마이징 인터페이스 제공

### 3.3. SafeHeaders 기능

#### 3.3.1. 기능 모호성 및 문서화 부족
- **파일**: `src/safe_headers/executor.rs`
- **문제**: HTTP Response Splitting 방지 기능이지만 이름과 문서 불명확
- **TODO**:
  - [ ] `HeaderSanitizer` 또는 `HttpHeaderValidator`로 이름 변경 검토
  - [ ] Rustdoc에 방어하는 공격 유형 설명 추가
  - [ ] `Shield::default()`에서 기본 활성화 여부를 사용자에게 명시

---

## 4. API 설계 및 DX 개선

### 4.1. 빌더 패턴 및 에러 처리

#### 4.1.1. `Shield` 빌더의 `Result<Self, Error>` 체이닝 불편
- **파일**: `src/shield.rs`
- **문제**: 메서드 체이닝 시 `?` 연산자 또는 `unwrap()` 강제
- **TODO**:
  - [ ] 검증을 `secure()` 시점으로 지연
  - [ ] 빌더 메서드는 `Self` 반환으로 변경
  - [ ] 또는 `build()` 단계를 추가하여 명시적 검증

#### 4.1.2. 에러 타입 통합
- **파일**: 각 모듈의 `*_error.rs` 파일들
- **문제**: 23개의 개별 에러 타입으로 사용자 부담 증가
- **TODO**:
  - [ ] 공통 `ShieldError` enum에 모든 에러 통합
  - [ ] 또는 카테고리별 그룹핑 (설정 에러, 실행 에러 등)
  - [ ] `Error::source()` 체인으로 세부 정보 제공

### 4.2. 모듈 구조 일관성

#### 4.2.1. 일관성 없는 디렉토리 구조
- **파일**: `src/csp/options/`, `src/csrf/options/`
- **문제**: 일부 모듈만 하위 디렉토리 구조 사용
- **TODO**:
  - [ ] 복잡한 모듈(`csp`, `csrf`)의 구조 정당성 문서화
  - [ ] 또는 단순 모듈과 일관되게 평탄화 검토

#### 4.2.2. `lib.rs`의 과도한 `pub use`
- **파일**: `src/lib.rs`
- **문제**: 내부 에러 타입 등 불필요한 API 노출
- **TODO**:
  - [ ] 최상위 노출은 `Shield`, `Options` 구조체로 제한
  - [ ] 세부 타입은 모듈 경로로 접근하도록 변경
  - [ ] `prelude` 모듈 추가 검토

### 4.3. 추상화 레벨

#### 4.3.1. 과도한 Executor 추상화
- **파일**: `src/executor.rs`
- **문제**: `FeatureExecutor`, `DynFeatureExecutor`, `CachedHeader` 등 불필요한 간접화
- **TODO**:
  - [ ] 정적 헤더 기능은 단순 함수로 단순화
  - [ ] 동적 기능만 트레이트 사용 정당화
  - [ ] 또는 추상화 이점(확장성, 테스트성) 문서화

#### 4.3.2. 매크로 디버깅 어려움
- **파일**: `src/executor.rs` (매크로들)
- **문제**: IDE "Go to Definition" 작동 불가
- **TODO**:
  - [ ] 매크로 사용 최소화
  - [ ] 또는 확장된 코드 예제를 문서에 포함

### 4.4. SameSite Cookie 설정

#### 4.4.1. 쿠키별 세밀한 제어 부재
- **파일**: `src/same_site/executor.rs`
- **문제**: 모든 쿠키에 동일 정책 적용
- **TODO**:
  - [ ] 쿠키 이름별 정책 맵 지원 (`HashMap<String, CookieMeta>`)
  - [ ] Path, Domain, Max-Age 등 추가 속성 강제 옵션 제공

### 4.5. NormalizedHeaders 구조체

#### 4.5.1. 파이프라인 정렬 비효율
- **파일**: `src/shield.rs`
- **문제**: 기능 추가 시마다 `Vec<PipelineEntry>` 재정렬
- **TODO**:
  - [ ] `BinaryHeap` 사용으로 삽입 시 자동 정렬
  - [ ] 또는 정렬된 상태 유지 보장

---

## 5. 문서화 및 배포

### 5.1. 코드 문서화

#### 5.1.1. Rustdoc 주석 전무
- **파일**: 전체 코드베이스
- **문제**: `///`, `//!` 주석이 거의 없음
- **TODO**:
  - [ ] 모든 공개 API에 Rustdoc 주석 추가
  - [ ] 각 모듈에 보안 위협 설명 추가
  - [ ] 사용 예제 포함 (`# Examples` 섹션)
  - [ ] `cargo doc --open`으로 확인

### 5.2. 예제 및 가이드

#### 5.2.1. `examples/` 디렉토리 부재
- **TODO**:
  - [ ] Axum 통합 예제 작성
  - [ ] Actix-web 통합 예제 작성
  - [ ] Rocket 통합 예제 작성
  - [ ] SPA, API 서버, 정적 사이트별 권장 설정 제공

#### 5.2.2. README.md 부재
- **파일**: `Cargo.toml` (readme 필드)
- **문제**: 프로젝트 루트에 `README.md` 없음 (패키징 오류)
- **TODO**:
  - [ ] 프로젝트 개요 작성
  - [ ] 빠른 시작 가이드 추가
  - [ ] 주요 기능 목록 정리
  - [ ] 라이선스 및 기여 가이드 포함

### 5.3. 문서 리소스

#### 5.3.1. `docs/` 디렉토리 비어있음
- **TODO**:
  - [ ] 아키텍처 설명 문서 작성
  - [ ] 보안 모범 사례 가이드 추가
  - [ ] 마이그레이션 가이드 (타 라이브러리에서 전환)

---

## 6. 성능 및 최적화

### 6.1. 의존성 관리

#### 6.1.1. CSRF 전용 의존성 분리
- **파일**: `Cargo.toml`
- **문제**: `hmac`, `sha2`, `rand`, `base64`가 항상 포함됨
- **TODO**:
  - [ ] `csrf` feature flag 추가
  - [ ] 기본 빌드에서 제외하여 슬림화
  - [ ] 문서에 feature flag 사용법 안내

#### 6.1.2. `url` 크레이트 사용 최소화
- **문제**: CSRF Origin 검증에만 사용
- **TODO**:
  - [ ] 간단한 수동 파싱으로 대체 검토
  - [ ] 또는 `csrf` feature에 포함

---

## 7. 테스트 및 품질 보증

### 7.1. 테스트 커버리지

#### 7.1.1. 커버리지 측정 및 개선
- **파일**: `tests/`, `src/*_test.rs`
- **현재 상태**: 테스트 파일은 존재하나 품질/커버리지 미확인
- **TODO**:
  - [ ] `cargo tarpaulin` 또는 `cargo llvm-cov` 실행
  - [ ] 80% 이상 커버리지 목표 설정
  - [ ] 공격 시나리오 테스트 추가 (보안 취약점 검증)

#### 7.1.2. 엣지 케이스 및 Proptest 강화
- **파일**: `tests/*proptest*.rs`
- **TODO**:
  - [ ] proptest 전략 확대 (더 많은 입력 조합)
  - [ ] 경계값 테스트 추가
  - [ ] 에러 케이스 전용 테스트 그룹 작성

### 7.2. CI/CD

#### 7.2.1. 지속적 통합 파이프라인
- **TODO**:
  - [ ] GitHub Actions 워크플로우 추가
  - [ ] 빌드, 테스트, 린트, 문서 생성 자동화
  - [ ] 보안 스캔 (`cargo audit`, `cargo deny`) 통합
  - [ ] 커버리지 리포트 자동 생성

---

## 📊 우선순위 요약

### 즉시 해결 (1-2주)
1. Rust 에디션 수정 (`edition = "2021"`)
2. CSRF 토큰 검증 로직 구현
3. Set-Cookie 병합 문제 해결
4. README.md 작성

### 단기 해결 (1-2개월)
1. CSP `child-src` 추가
2. Referrer-Policy fallback 지원
3. Fetch Metadata 통합 가이드 작성
4. CSRF Origin 검증 개선
5. Rustdoc 주석 추가 (주요 API)

### 중기 개선 (3-6개월)
1. 요청/응답 인터페이스 분리
2. API 재설계 (빌더 패턴, 에러 통합)
3. 예제 디렉토리 구축
4. 테스트 커버리지 80% 달성
5. 의존성 feature flag 분리

### 장기 검토 (6개월 이상)
1. 과도한 추상화 단순화
2. 모듈 구조 일관성 개선
3. 성능 최적화 (벤치마크 기반)
4. 커뮤니티 피드백 반영

---

## 🔗 참고 자료

- **표준 문서**:
  - [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
  - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
  - [RFC 6265 (HTTP State Management)](https://datatracker.ietf.org/doc/html/rfc6265)
  - [RFC 7230 (HTTP/1.1 Message Syntax)](https://datatracker.ietf.org/doc/html/rfc7230)

- **CSP**:
  - [CSP Level 3 Spec](https://www.w3.org/TR/CSP3/)
  - [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

- **Rust 문서**:
  - [The Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
  - [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)

---

**문서 버전**: 1.0  
**마지막 업데이트**: 2025-10-31


## 📎 부록: 기존 보고서 포함 범위 및 추적성

아래는 `report_old.md`의 주요 항목이 본 문서에 어떻게 반영되었는지의 매핑과, 누락되었던 “문제 없음” 확인 항목 및 보완 TODO를 추가하여 전체 포함성을 보장합니다.

- A. Fetch Metadata 정정(검증 로직 존재) → 본문 3.2.1, 3.2.2에 반영(통합 가이드/Hook TODO 포함)
- B. CSRF 실행기 검증 부재/Origin 검증 한계 → 본문 1.2, 3.1.1, 3.1.3에 반영
- C. Permissions-Policy Report-Only/Feature-Policy 혼선 → 본문 2.3.2에 반영
- D. Permissions-Policy Allowlist 인용 처리 → 본문 2.3.1에 반영
- E. Set-Cookie 병합/개행 위험 → 본문 1.3에 반영
- F. 최상위 `pub use` 과다 → 본문 4.2.2에 반영
- G. 패키징/문서(README, docs/) 결함 → 본문 5.2.2, 5.3에 반영
- H. CSP `child-src`/`report-uri` 누락, Deprecated 표기 → 본문 2.1.1, 2.1.2, 2.1.3에 반영
- I. 관측성/로깅 Hook 부재 → 본문 3.2.1, 3.2.2에 반영
- J. 기능 플래그/슬림 빌드 → 본문 6.1.1에 반영
- K. 요청/응답 경계 분리 필요 → 본문 1.4에 반영
- L. 모듈 전수 검토(커버리지 체크리스트) → 본 부록의 “검토 완료(문제 없음) 항목”으로 요약 반영
- M. HSTS `preload` 최소 max-age 재검토(1년 충족) → 본문 2.4.1에 반영
- N. Set-Cookie 직렬화 명세 위반 상세 → 본문 1.3에 반영
- O. 요청/응답 컨텍스트 혼합 위험 상세 → 본문 1.4에 반영

추가로, `report_old.md`에서 “특별한 문제 없음(OK)”으로 확인된 항목을 본 문서에도 기록합니다.

검토 완료(문제 없음) 항목:
- COEP: 표준 정책값 및 Report-Only 모드 구현 정상
- COOP: 표준 정책값 및 Report-Only 모드 구현 정상
- CORP: 표준 정책값 구현 정상(Report-Only 개념 없음은 표준에 부합)
- Clear-Site-Data: 섹션 직렬화/검증 정상
- Origin-Agent-Cluster: `?1` 활성화/비활성 옵션 정상
- X-Content-Type-Options: 항상 `nosniff` 설정(단일 유효값) 정상
- X-DNS-Prefetch-Control: on/off 지원 및 기본값 off 적절
- X-Powered-By: 제거 기능 정상
- CSP 세부(소스 표현, Sandbox 토큰, Trusted Types): 표준 준수 확인

보완/문서 TODO(경미하지만 유의미):
- [ ] X-Frame-Options: deprecated `ALLOW-FROM` 비지원 사유와 CSP `frame-ancestors` 대체 전략을 Rustdoc/가이드에 명시
- [ ] PolicyMode/Report-Only 지원 범위: `features.md` 및 문서에 기능별 지원 현황과 한계 명시(Chromium 호환성 주석 포함)
- [ ] 일부 옵션이 `Infallible` 에러 타입을 사용(현재 검증 없음) → 향후 검증 추가 시의 호환성 고려: 공통 에러 타입 또는 선택적 트레이트 구현 전략 문서화

정보성 참고(변경 불필요):
- 실행 순서 상수(`constants.rs`)는 안전한 기본 순서를 따름: SafeHeaders(0) → FetchMetadata(1) → … → Clear-Site-Data(마지막)
