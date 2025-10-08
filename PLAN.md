# 개발 구현 계획 (Rust 코어 라이브러리)

본 계획은 `POLICY.md`에 정의된 보안 정책을 Rust 코어 라이브러리 형태로 구현하기 위한 실제 개발 절차를 정리한 것입니다. 모든 섹션은 릴리스 우선순위(1단계 → 2단계 → 3단계)에 따라 정렬되어 있으며, 각 작업 단계는 관련 국제 표준과 브라우저 표준 정책을 근거로 작성했습니다.

## 아키텍처 원칙 (요구사항 검토 결과)
- **외부 프레임워크 배제**: 모든 구현 및 테스트는 표준 라이브러리와 자체 모듈만 사용하며, 특정 웹 프레임워크 의존성을 문서에서 완전히 제거했습니다. 독립 실행형 코어 라이브러리로 유지 가능합니다.
- **기능별 전용 모듈 디렉터리**: 각 보안 기능은 `src/<feature>/` 구조(예: `src/csp/`, `src/hsts/`)로 분리하고, 옵션/검증/테스트 자원을 모듈 내부에 배치합니다. 모듈 경계가 명확해 유지보수와 기능 토글이 용이합니다.
- ~~**`Shield` 단일 진입점**: `Shield::new()`는 어떠한 기능도 활성화하지 않은 상태로 초기화되며, 체인 메서드 `Shield::<feature>(options)`를 호출한 경우에만 기능이 추가됩니다. 기존 계획의 `ShieldBuilder` 서술을 모두 갱신했습니다.~~
- **옵션 구조체의 자체 빌더 패턴**: 각 `*Options`는 체이닝 메서드(e.g. `CspOptions::default().with_directive(...)`)를 제공하되 `build()` 함수는 두지 않습니다. 최종 검증은 `Shield` 체인 메서드 내부 `validate()` 호출로 수행합니다.
- **불변 추가 모델**: 체인 메서드는 기능 추가만 허용하며 비활성화/제거 API는 제공합니다. 동일 기능을 재호출하면 이전 구성이 덮어쓰여 최신 설정으로 치환됩니다.
- ~~**헤더 파이프라인**: 모든 기능은 사전에 정의된 실행 순서에 따라 `Vec<FeatureStage>` 파이프라인으로 등록되며, `secure` 호출 시 순차적으로 적용됩니다.~~
- **실행 함수 명명**: 헤더 적용 시 `Shield::secure(headers)`를 사용합니다.
- ~~**헤더 정규화 전략**: 실행 함수는 입력 `Headers`를 모두 소문자로 변환한 `NormalizedHeaders`(내부 전용 타입)로 처리하고, 원본 케이스를 유지한 최종 `Headers`를 반환합니다. 역정규화 시 RFC 7230 헤더 케이스 관례를 참고합니다.~~
- ~~**정적 값 상수화**: 모든 헤더 키/상수 값은 각 모듈에서 `pub const`로 정의하여 재사용합니다.~~

위 항목들은 구현 가능하며, 아래 세부 계획에 즉시 반영되었습니다.

## 테스트 규칙(범용)
1. 테스트 파일엔 주석을 남기지 않는다.
2. 절대 중복된 테스트를 작성하지 않는다.

## 통합 테스트 규칙
1. 기능 단위로 파일을 생성하며 파일명은 기능명으로 한다.
2. 테스트 케이스명은 BDD 패턴을 따른다. (given|should|it 등등 다양하게)_when_then 패턴으로 영어로 작성
3. AAA 패턴을 사용하고 하나의 테스트 함수는 하나의 시나리오만 포함한다.

## 유닛 테스트 규칙
모든 개발 작업은 아래 단위 테스트 규칙을 준수해야 합니다.

1. 외부 파일로 작성. 대상 파일과 동일한 디렉토리에 대상 파일명_test.rs 로 명명
2. mod 함수명 으로 함수명 단위 모듈화
3. 테스트 케이스명은 BDD 패턴을 따른다. (given|should|it 등등 다양하게)_when_then 패턴으로 영어로 작성
4. 모듈부터 테스트 케이스까지 최대 3뎁스
5. 테스트에 필요한 헬퍼나 유틸은 tests/common 에 있는 것을 최대한 활용한다.
6. 만약 필요한 헬퍼나 유틸이 이 없는 경우 중복을 피하여 추가하고, 만약 기존 헬퍼나 유틸의 기능이 조금 부족해서 사용하지 못하는 경우 기존 기능을 범용화하여 수정한다.
7. 테스트 케이스는 작고 빠르게 유지한다.
8. 테스트 케이스는 테스트 대상 함수의 순수 기능에 대한 테스트만 한다.(함수 내에서 호출하는 외부 기능 검증하지 않음)
9. 테스트 케이스는 기능, 에러 처리, 엣지 케이스를 엄격하고 광범위하게 작성한다.
10. AAA 패턴을 사용하고 하나의 테스트 함수는 하나의 시나리오만 포함한다.
11. 테스트 간 상태공유는 금지하고 독립성을 보장한다.
12. 중복 된 테스트는 최대한 지양해라
13. 단위 격리(Isolation) 원칙: 테스트 대상 로직 내에서 사용하는 외부 기능은 테스트 범위에 포함하지 않는다. 외부 기능에 의존하지 않고 테스트 대상의 로직만 엄격하게 테스트한다.


## 파이프라인 실행 순서 개요
| 순서 | 단계 | 기능 |
| --- | --- | --- |
| 1 | 1단계 | Content Security Policy (CSP) |
| 2 | 1단계 | X-Powered-By 제거 |
| 3 | 1단계 | Strict-Transport-Security (HSTS) |
| 4 | 1단계 | X-Content-Type-Options |
| 5 | 1단계 | CSRF 토큰 모듈 |
| 6 | 1단계 | SameSite Cookie 속성 관리 |
| 7 | 1단계 | Cross-Origin-Embedder-Policy (COEP) |
| 8 | 1단계 | Cross-Origin-Opener-Policy (COOP) |
| 9 | 1단계 | Cross-Origin-Resource-Policy (CORP) |
| 10 | 2단계 | Strict CSP 고급 프로파일 |
| 11 | 2단계 | X-Frame-Options |
| 12 | 2단계 | Referrer-Policy |
| 13 | 2단계 | Origin-Agent-Cluster |
| 14 | 2단계 | X-Download-Options |
| 15 | 2단계 | X-Permitted-Cross-Domain-Policies |
| 16 | 2단계 | Permissions-Policy |
| 17 | 3단계 | X-DNS-Prefetch-Control |
| 18 | 3단계 | Clear-Site-Data |

`Shield::secure`는 이 표의 순서를 기준으로 파이프라인을 실행합니다.

## Shield 코어 및 헤더 정규화 계층
- **목표**: 모든 기능이 공통으로 사용하는 `Shield` 구조체와 `NormalizedHeaders` 타입을 구축합니다.
- **구현 작업**
   1. ~~`src/shield/mod.rs`에 `pub struct Shield` 정의. `Shield::new()`는 비활성화 상태의 기능 레지스트리를 초기화합니다.~~
  2. 각 체인 메서드(예: `content_security_policy`, `strict_transport_security`, `csrf`)는 기능별 상태(`FeatureStage`)를 파이프라인 벡터에 등록하고, 옵션이 있으면 `validate()` 호출 후 내부 구성을 최신 상태로 덮어씁니다.
  3. 파이프라인은 `FeatureStage { order: FeatureOrder, apply: fn(&mut NormalizedHeaders) -> Result<(), ShieldError> }` 형태로 구성하여 실행 순서를 고정합니다.
   4. ~~`src/headers/normalized.rs`에 `NormalizedHeaders` 타입과 소문자화/역정규화 로직을 구현합니다. 입력은 `HeaderMap` 또는 `(String, String)` 쌍으로 받아, RFC 7230 준수 여부를 검사합니다.~~
   5. ~~`src/constants.rs`(또는 각 모듈)에서 모든 헤더 키와 상수 값을 `pub const`로 정의하여 중복을 방지합니다.~~
  6. `Shield::secure(mut headers: HeaderMap) -> Result<HeaderMap, ShieldError>`를 구현하여: (a) 입력 헤더를 `NormalizedHeaders`로 변환, (b) 파이프라인 순서대로 각 기능 모듈의 `apply(&mut NormalizedHeaders)`를 호출, (c) 최종 결과를 원래 케이스 규칙에 맞춰 `HeaderMap`으로 복원합니다.
   7. ~~`ShieldError` 열거형을 정의해 모든 `validate()`/`apply()` 오류를 수집하고, 실패 시 원본 헤더를 변경하지 않은 채 반환하는 전략을 문서화합니다.~~
- **주의/검증**
  - 기능 적용 순서는 1단계 → 2단계 → 3단계 순으로 고정하고, 상호 의존 관계가 있는 경우(`COEP` ↔ `CORP`)에 대한 순서 테스트를 추가합니다.
  - `NormalizedHeaders` 변환 시 헤더 값 트리밍, 금지 문자 검사 등을 포함해 헤더 인젝션을 방지합니다.
- **참조 규격**: RFC 7230/7231 (HTTP 메시지 문법), Rust API Guidelines



## 1. Content Security Policy (CSP) 기본 구현
- **목표**: 기본 CSP 및 Report-Only 헤더를 생성하는 안전한 API 제공.
- **파이프라인 순서**: 1 (1단계)
- ~~**정적 상수**: `const HEADER_CONTENT_SECURITY_POLICY`, `const HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY`, `const HEADER_REPORT_TO`~~
- **구현 작업**
   1. ~~`src/csp/mod.rs`와 `src/csp/options.rs`를 생성하고, `CspDirective`, `CspOptions`, `CspPolicy` 구조를 정의합니다.~~
   2. ~~`CspOptions`는 체이닝 메서드(e.g. `with_directive`, `with_report_only_group`)를 제공하며, `validate()` 내부에서 디렉티브 문법을 확인합니다.~~
   3. ~~`Shield::content_security_policy(options: CspOptions)` 체인 메서드를 추가하고, 내부에서 `options.validate()` 호출 후 `NormalizedHeaders`에 CSP/Report-To 헤더를 삽입합니다.~~
  4. ~~기본 지침에 맞춘 1단계 프리셋(`CspOptions::strict_minimum()`)과 Report-Only 모드 토글을 제공하되, 최종 적용은 `Shield::secure(headers)`에서 수행합니다.~~
   5. ~~단위 테스트: 미설정 시 헤더 미삽입, Report-Only 활성화 시 `Content-Security-Policy-Report-Only`가 정확히 직렬화되는지 확인합니다.~~
- **주의/검증**
  - W3C CSP Level 3 문법 검증을 위해 `csp::validator` 모듈에서 금지 토큰 검사 로직을 유지합니다.
  - nonce/hash 값은 라이브러리 소비자가 주입하므로, API는 `Cow<'a, str>` 기반으로 유연성 보장하되 `validate()`에서 길이/문자셋 확인을 수행합니다.
- **참조 규격**: W3C CSP Level 3, OWASP Top 10 A03:2021

## 2. X-Powered-By 제거
- **목표**: 서버 정보 노출 방지를 위한 공통 미들웨어 제거 기능 제공.
- **파이프라인 순서**: 2 (1단계)
- **정적 상수**: `const HEADER_X_POWERED_BY`
- **구현 작업**
  1. `src/x_powered_by/mod.rs`에서 제거 로직과 `XPoweredByRemoval` 유틸 정의.
  2. `Shield::x_powered_by_disabled()` 체인 메서드에서 `NormalizedHeaders`에서 해당 키를 제거하고, 반환 헤더에는 원본 케이스(`X-Powered-By`)를 유지하지 않도록 명시합니다.
  3. 단위 테스트: 입력 헤더에 대소문자가 섞인 경우에도 제거되는지 검증합니다.
- **주의/검증**: 헤더 키 케이스 민감도(HTTP/1.1은 케이스 무시)이므로 정규화 로직과 연계해 제거합니다.
- **참조 규격**: OWASP ASVS 4.0 V14.5, CWE-200

## 3. Strict-Transport-Security (HSTS)
- **목표**: HTTPS 강제 및 프리로드 지원.
- **파이프라인 순서**: 3 (1단계)
- **정적 상수**: `const HEADER_STRICT_TRANSPORT_SECURITY`
- **구현 작업**
  1. `src/hsts/` 디렉터리에 `mod.rs`, `options.rs`, `error.rs`를 생성하고 `HstsOptions { max_age, include_subdomains, preload }` 정의.
  2. `HstsOptions`는 `with_max_age`, `include_subdomains`, `enable_preload` 메서드로 체이닝을 지원하며, `validate()`에서 프리로드 조건(`max_age >= 31536000`, `include_subdomains=true`)을 확인합니다.
  3. `Shield::strict_transport_security(options: HstsOptions)` 체인 메서드에서 `options.validate()?` 후 `NormalizedHeaders`에 헤더 삽입.
  4. 테스트: 잘못된 조합 시 `ShieldError::InvalidHsts` 반환, 정상 조합은 헤더 문자열이 RFC 6797 형식임을 검증합니다.
- **주의/검증**
  - RFC 6797 준수: HTTP 응답 코드 2xx/3xx에서만 사용되도록 문서화.
  - 로컬 개발(HTTP) 환경에서는 비활성화 안내.
- **참조 규격**: RFC 6797, Chromium HSTS preload 정책

## 4. X-Content-Type-Options
- **목표**: MIME 스니핑 방지를 위해 `nosniff` 헤더 설정.
- **파이프라인 순서**: 4 (1단계)
- **정적 상수**: `const HEADER_X_CONTENT_TYPE_OPTIONS`, `const VALUE_NOSNIFF`
- **구현 작업**
  1. `src/x_content_type_options/mod.rs`에서 `XContentTypeOptions` 모듈 정의하고 `NOSNIFF_VALUE` 상수 유지.
  2. `Shield::x_content_type_options()` 체인 메서드는 입력 옵션 없이 `NormalizedHeaders`에 `nosniff`를 삽입하며, 이미 존재할 경우 덮어쓰기 전략을 문서화합니다.
  3. 단위 테스트: 중복 호출 시 헤더가 한 번만 존재하는지 검증합니다.
- **주의/검증**: HTTP/2에서 중복 헤더 금지 검증.
- **참조 규격**: OWASP Secure Headers Project

## 5. CSRF 토큰 모듈
- **목표**: Double Submit Cookie 패턴을 지원하는 토큰 생성/검증 기능 제공.
- **파이프라인 순서**: 5 (1단계)
- **정적 상수**: `const HEADER_SET_COOKIE`, `const HEADER_CSRF_TOKEN`, `const COOKIE_PREFIX_SECURE`
- **구현 작업**
  1. `src/csrf/` 디렉터리에 `mod.rs`, `options.rs`, `token.rs`를 생성하고 `CsrfOptions`, `CsrfTokenService` trait, `HmacCsrfService` 구현 (SHA-256) 정의.
  2. `CsrfOptions`는 `with_cookie_name`, `rotate_on`, `with_token_length` 등의 체이닝 메서드를 제공하며, `validate()`에서 토큰 최소 길이와 회전 이벤트 구성을 확인합니다.
  3. `Shield::csrf(options: CsrfOptions)` 체인 메서드에서 `options.validate()` 호출 후 토큰 생성/검증 핸들러를 등록하고, `NormalizedHeaders`에 `Set-Cookie` 지침을 주입합니다.
  4. 모듈 내부 단위 테스트로 성공/실패 경로를 검증하고, `no_std` 환경 호환 여부를 확인합니다.
- **주의/검증**
  - RFC 6265bis에 따른 쿠키 속성 검증 (Secure/Lax 기본값 강제).
  - OWASP CSRF Cheat Sheet에 따른 토큰 길이(≥128bit) 확인.
- **참조 규격**: OWASP CSRF Cheat Sheet, RFC 6265bis, CWE-352

## 6. SameSite Cookie 속성 관리
- **목표**: 모든 애플리케이션 쿠키에 안전한 SameSite 기본값 제공.
- **파이프라인 순서**: 6 (1단계)
- **정적 상수**: `const HEADER_SET_COOKIE`, `const SAMESITE_LAX`, `const SAMESITE_STRICT`, `const SAMESITE_NONE`
- **구현 작업**
  1. `src/same_site/mod.rs`에 `SameSiteOptions`, `SameSitePolicy` enum(Lax/Strict/None), `CookieMeta` 구조체 정의.
  2. `SameSiteOptions`는 `enforce_secure()`, `http_only(bool)`, `strict_mode()` 등 체이닝 메서드를 제공하고, `validate()`에서 `None` + `!Secure` 조합 차단.
  3. `Shield::same_site(options: SameSiteOptions)` 체인 메서드가 `validate()` 이후 쿠키 메타데이터 테이블을 갱신하여 `Secure`/`HttpOnly` 기본값을 강제합니다.
  4. 단위 테스트: `None` + `!Secure` 조합에서 에러 반환, 기본 Lax 정책이 적용되는지 확인.
- **주의/검증**: 사용자 정의 쿠키 주입 시에도 기본 정책 덮어쓰기 지원.
- **참조 규격**: RFC 6265bis, Chrome SameSite Updates

## 7. Cross-Origin-Embedder-Policy (COEP)
- **목표**: 헤더 `Cross-Origin-Embedder-Policy` 기본값 `require-corp` 제공.
- **파이프라인 순서**: 7 (1단계)
- **정적 상수**: `const HEADER_CROSS_ORIGIN_EMBEDDER_POLICY`, `const VALUE_REQUIRE_CORP`, `const VALUE_CREDENTIALLESS`
- **구현 작업**
  1. `src/coep/mod.rs`에 enum(`RequireCorp`, `Credentialless`), `CoepOptions` 정의.
  2. `CoepOptions`는 `require_corp()` 기본값을 제공하고, `credentialless()` 호출 시 추가 검증(캐시/쿠키 영향 표기)을 수행합니다.
  3. `Shield::coep(options: CoepOptions)` 체인 메서드에서 `options.validate()` 후 `NormalizedHeaders`에 헤더 삽입.
- **주의/검증**: credentialless 선택 시 캐시/쿠키 동작 변화에 대한 주석 추가.
- **참조 규격**: WHATWG Fetch, W3C HTML Standard

## 8. Cross-Origin-Opener-Policy (COOP)
- **목표**: `same-origin` 기본값 제공.
- **파이프라인 순서**: 8 (1단계)
- **정적 상수**: `const HEADER_CROSS_ORIGIN_OPENER_POLICY`, `const VALUE_SAME_ORIGIN`, `const VALUE_SAME_ORIGIN_ALLOW_POPUPS`
- **구현 작업**
  1. `src/coop/mod.rs`에서 enum(`UnsafeNone`, `SameOriginAllowPopups`, `SameOrigin`)과 `CoopOptions` 정의.
  2. `CoopOptions` 기본값을 `same_origin()`으로 설정하고, `allow_popups()` 호출 시 추가 주석을 포함합니다.
  3. `Shield::coop(options: CoopOptions)` 체인 메서드에서 `options.validate()` 후 헤더를 적용합니다.
- **참조 규격**: WHATWG HTML Standard

## 9. Cross-Origin-Resource-Policy (CORP)
- **목표**: 리소스 접근 정책을 선언.
- **파이프라인 순서**: 9 (1단계)
- **정적 상수**: `const HEADER_CROSS_ORIGIN_RESOURCE_POLICY`, `const VALUE_SAME_ORIGIN`, `const VALUE_SAME_SITE`, `const VALUE_CROSS_ORIGIN`
- **구현 작업**
  1. `src/corp/mod.rs`에서 enum(`SameOrigin`, `SameSite`, `CrossOrigin`), `CorpOptions` 정의.
  2. `CorpOptions` 기본값을 `same_origin()`으로 설정하고, 허용 범위 확장 시 명시적 메서드(`allow_same_site()`, `allow_cross_origin()`).
  3. `Shield::corp(options: CorpOptions)` 체인 메서드에서 `options.validate()` 실행 후 헤더 직렬화 결과를 테스트로 검증합니다.
- **참조 규격**: WHATWG Fetch, OWASP Secure Headers

---

## 10. Strict CSP 고급 프로파일 (2단계)
- **목표**: nonce/hash + `strict-dynamic`를 포함한 강화 정책 지원.
- **파이프라인 순서**: 10 (2단계)
- **정적 상수**: `const DIRECTIVE_STRICT_DYNAMIC`, `const DIRECTIVE_REQUIRE_TRUSTED_TYPES`
- **구현 작업**
  1. `src/csp/advanced.rs`에 강화 정책 전용 헬퍼 추가(`with_nonce`, `with_hash`, `enable_strict_dynamic`).
  2. `CspOptions`에 `enable_nonce_generation(NonceGenerator)` 등 체이닝 메서드를 확장하고, `validate()`에서 nonce 재사용 금지 룰을 확인합니다.
  3. `Shield::content_security_policy` 호출 시 강화 옵션이 설정되어 있으면 `Content-Security-Policy`와 `Report-To`를 동시에 갱신하도록 합니다.
- **주의/검증**: nonce 재사용 금지 정책(요청 단위) 문서화, 테스트에서 중복 감지.
- **참조 규격**: Google Strict CSP, Trusted Types (Chromium)

## 11. X-Frame-Options (레거시 호환)
- **목표**: 프레임 보호 레거시 지원.
- **파이프라인 순서**: 11 (2단계)
- **정적 상수**: `const HEADER_X_FRAME_OPTIONS`, `const VALUE_DENY`, `const VALUE_SAMEORIGIN`
- **구현 작업**
  1. `src/x_frame_options/mod.rs`에서 enum(`Deny`, `SameOrigin`), `XFrameOptions` 구조체 정의.
  2. `Shield::x_frame_options(options: XFrameOptions)` 체인 메서드는 명시적으로 호출된 경우에만 헤더를 추가하고, CSP `frame-ancestors`와 충돌 시 경고 로그를 남깁니다.
  3. 테스트: 지원하지 않는 값 입력 시 `ShieldError::InvalidXFrameOptions` 반환 여부 확인.
- **주의/검증**: RFC 7034 요구사항(허용 값 검증).
- **참조 규격**: RFC 7034

## 12. Referrer-Policy
- **목표**: `strict-origin-when-cross-origin` 기본값 제공.
- **파이프라인 순서**: 12 (2단계)
- **정적 상수**: `const HEADER_REFERRER_POLICY`, `const VALUE_STRICT_ORIGIN_WHEN_CROSS_ORIGIN`
- **구현 작업**
  1. `src/referrer_policy/mod.rs`에서 enum(`NoReferrer`, `SameOrigin`, `StrictOriginWhenCrossOrigin`, 등)과 `ReferrerPolicyOptions` 정의.
  2. `Shield::referrer_policy(options: ReferrerPolicyOptions)` 체인 메서드는 기본값을 `strict_origin_when_cross_origin()`으로 설정하고, 필요 시 다른 정책을 선택할 수 있도록 합니다.
- **주의/검증**: GDPR/개인정보 보호 관련 주석 포함.
- **참조 규격**: W3C Referrer Policy, GDPR Recital 39

## 13. Origin-Agent-Cluster
- **목표**: 헤더 `Origin-Agent-Cluster: ?1` 제공.
- **파이프라인 순서**: 13 (2단계)
- **정적 상수**: `const HEADER_ORIGIN_AGENT_CLUSTER`, `const VALUE_ENABLE_ORIGIN_AGENT_CLUSTER`, `const VALUE_DISABLE_ORIGIN_AGENT_CLUSTER`
- **구현 작업**
  1. `src/origin_agent_cluster/mod.rs`에서 `OriginAgentClusterOptions` 정의(`enable()`/`disable()`).
  2. `Shield::origin_agent_cluster(options: OriginAgentClusterOptions)` 체인 메서드는 `?1` 또는 `?0` 중 하나를 설정합니다.
- **주의/검증**: 비활성화 옵션 제공 (`?0`).
- **참조 규격**: WHATWG HTML Standard

## 14. X-Download-Options
- **목표**: `noopen` 설정 제공.
- **파이프라인 순서**: 14 (2단계)
- **정적 상수**: `const HEADER_X_DOWNLOAD_OPTIONS`, `const VALUE_NOOPEN`
- **구현 작업**
  1. `src/x_download_options/mod.rs`에서 `XDownloadOptions` 모듈과 상수 정의.
  2. `Shield::x_download_options()` 체인 메서드는 `noopen`을 적용하며, 추가 옵션이 필요 없는 경우에도 `NormalizedHeaders`와의 호환성을 유지합니다.
- **주의/검증**: Internet Explorer 전용임을 주석으로 명시.
- **참조 규격**: OWASP Secure Headers

## 15. X-Permitted-Cross-Domain-Policies
- **목표**: Flash/PDF 대응 헤더 설정.
- **파이프라인 순서**: 15 (2단계)
- **정적 상수**: `const HEADER_X_PERMITTED_CROSS_DOMAIN_POLICIES`, `const VALUE_NONE`, `const VALUE_MASTER_ONLY`, `const VALUE_BY_CONTENT_TYPE`, `const VALUE_ALL`
- **구현 작업**
  1. `src/x_permitted_cross_domain_policies/mod.rs`에서 enum(`None`, `MasterOnly`, `ByContentType`, `All`)과 `XPermittedCrossDomainPoliciesOptions` 정의.
  2. `Shield::x_permitted_cross_domain_policies(options: XPermittedCrossDomainPoliciesOptions)` 체인 메서드는 기본값을 `none()`으로 유지하고, 필요 시 다른 값을 선택할 수 있도록 합니다.
- **주의/검증**: 현대 환경에서 영향이 제한적임을 문서화.
- **참조 규격**: Adobe Cross-Domain Policy Spec

## 16. Permissions-Policy
- **목표**: 브라우저 기능 제어 템플릿 제공.
- **파이프라인 순서**: 16 (2단계)
- **정적 상수**: `const HEADER_PERMISSIONS_POLICY`
- **구현 작업**
  1. `src/permissions_policy/` 디렉터리에서 선언형 DSL 구현(`policy!("geolocation" => self)`), 내부적으로 `PermissionsPolicyOptions`에 매핑합니다.
  2. `PermissionsPolicyOptions`는 체이닝 메서드로 개별 기능 허용/차단을 구성하고, `validate()`에서 문법 오류를 검증합니다.
  3. `Shield::permissions_policy(options: PermissionsPolicyOptions)` 체인 메서드에서 직렬화된 헤더를 적용합니다.
- **주의/검증**: 브라우저별 지원 편차 문서화, 실험적 기능 플래그 분리.
- **참조 규격**: WICG Permissions Policy

## 17. X-DNS-Prefetch-Control
- **목표**: 프리페치 on/off 제어.
- **파이프라인 순서**: 17 (3단계)
- **정적 상수**: `const HEADER_X_DNS_PREFETCH_CONTROL`, `const VALUE_ON`, `const VALUE_OFF`
- **구현 작업**
  1. `src/x_dns_prefetch_control/mod.rs`에서 enum(`On`, `Off`)과 `XdnsPrefetchControlOptions` 정의, 기본값은 `off()`.
  2. `Shield::x_dns_prefetch_control(options: XdnsPrefetchControlOptions)` 체인 메서드는 옵션을 검증 후 헤더를 적용합니다.
- **주의/검증**: HTML `<meta>`와 동시 구성 시 우선순위 안내.
- **참조 규격**: HTML dns-prefetch Hint, OWASP Secure Headers

## 18. Clear-Site-Data (선택)
- **목표**: 보안 사고 대응 시 상태 초기화 지원.
- **파이프라인 순서**: 18 (3단계)
- **정적 상수**: `const HEADER_CLEAR_SITE_DATA`, `const VALUE_CACHE`, `const VALUE_COOKIES`, `const VALUE_STORAGE`, `const VALUE_EXECUTION_CONTEXTS`
- **구현 작업**
  1. `src/clear_site_data/` 디렉터리에서 플래그 비트마스크(`CACHE`, `COOKIES`, `STORAGE`, `EXECUTION_CONTEXTS`)와 `ClearSiteDataOptions` 정의.
  2. `ClearSiteDataOptions`는 `cookies()`, `storage()`, `execution_contexts()` 등 체이닝 메서드를 제공하며, `validate()`에서 최소 한 개 이상의 플래그가 설정되었는지 확인합니다.
  3. `Shield::clear_site_data(options: ClearSiteDataOptions)` 체인 메서드는 HTTPS 환경 여부 확인(선택적 `enforce_https` 플래그) 후 헤더를 적용합니다.
- **주의/검증**: 전체 쿠키 삭제로 인한 세션 손실 경고를 문서에 강조.
- **참조 규격**: W3C Clear Site Data

---

## 19. 문서화 및 예제 코드 배포
- **목표**: 라이브러리 사용자를 위한 가이드 제공.
- **구현 작업**
  1. `examples/` 폴더에 순수 Rust `main` 예제(`shield_basic.rs`)를 추가하여 `Shield::new().content_security_policy(...).strict_transport_security(...)` 흐름을 시연합니다.
  2. `README.md`에 각 체인 메서드 사용법과 옵션 검증 규칙, `NormalizedHeaders` 개념을 요약합니다.
  3. `README.md`에 모든 기능이 기본 비활성화 상태임을 강조하고, 파이프라인 순서를 표로 정리합니다.
  4. `POLICY.md` ↔ `PLAN.md` ↔ 실제 코드 간 추적표를 도표로 제공.
- **주의/검증**: 브라우저 동작 설명은 최소화하고 헤더 설정 방법 중심으로 유지.
- **참조 규격**: Rustdoc Best Practices, Cargo Examples Guide

---

## 20. 릴리스 및 유지보수 절차
- **목표**: 릴리스 검증과 장기 유지 전략 확립.
- **구현 작업**
  1. `cargo-husky` 훅에 포맷/린트/테스트 자동 실행.
  2. `CHANGELOG.md`에 SemVer 준수 릴리스 노트 작성.
  3. 보안 이슈 대응 체계: 헤더 표준 업데이트 모니터링(WHATWG, W3C, RFC 편람).
- **주의/검증**: 호환성 파괴 변경 시 메이저 버전 증가.
- **참조 규격**: SemVer 2.0.0, Rust Security Advisory DB

---

**검증 체크리스트**
- [ ] 모든 1단계 기능 단위 테스트/프로퍼티 테스트 통과
- [ ] 문서 예제 코드가 최신 API와 일치
- [ ] 헤더 값 직렬화가 각 표준의 문법 요구사항을 충족
- [ ] CI 파이프라인에 릴리스 전 자동 검증 포함
