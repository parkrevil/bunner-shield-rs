# Bunner Shield RS 라이브러리 검토 보고서

## 분석 및 개선 제안

### 1. 구조, 코딩 스타일, 패턴의 일관성

#### 긍정적인 점
- **모듈화**: 기능별(CSP, HSTS, CORP 등)로 모듈이 명확하게 분리되어 있어 구조가 깔끔하고 이해하기 쉽습니다.
  - **타당성 검토:** `src/` 하위에 각 정책별 디렉터리(예: `src/csp/`, `src/hsts/`, `src/corp/`)가 존재하며 `mod.rs`에서 re-export 하는 구조를 확인했습니다.
- **파일 구조**: 각 기능 모듈 내에 `mod.rs`, `options.rs`, `executor.rs`, `*_test.rs` 패턴이 일관되게 사용되어 예측 가능성이 높습니다.
  - **타당성 검토:** `src/hsts/`, `src/coop/`, `src/corp/` 등에서 동일한 파일 패턴이 유지되고, 테스트 파일이 `#[path = "..."]`로 연결되어 있음을 확인했습니다.
- **네이밍**: `*Options`, `*Policy`, `*Executor` 등의 네이밍 컨벤션이 일관되어 DX(개발자 경험)에 긍정적입니다.
  - **타당성 검토:** 예를 들어 `src/coop/options.rs`의 `CoopOptions`와 `CoopPolicy`, `src/coop/executor.rs`의 `Coop`가 일관된 명명 규칙을 따르며 다른 모듈도 동일한 패턴을 유지합니다.

- **`executor.rs`의 추상화**: 현재 각 기능의 `executor.rs`는 `execute` 메소드를 포함하는 유사한 구조를 가집니다. 이를 `Executor` 트레이트(trait)로 추상화하여 모든 Executor가 이를 구현하도록 강제하면, 코드의 일관성과 재사용성이 더욱 향상될 것입니다.
  ```rust
  // 제안 (src/executor.rs 또는 새로운 파일)
  pub trait Executor {
      fn execute(&self, headers: &mut NormalizedHeaders);
  }
  ```
  각 모듈의 `executor`는 이 트레이트를 구현하게 됩니다.
  - **타당성 검토:** 현재 `src/executor.rs`의 `FeatureExecutor`/`DynFeatureExecutor` 조합으로 동작하지만 공통 추상화가 없어 각 정책 executor가 유사 구현을 반복하고 있음을 코드에서 확인했습니다.

- **`csp` 모듈의 복잡성**: `csp` 모듈은 다른 모듈에 비해 내부 구조가 매우 복잡합니다 (`options/` 하위의 수많은 파일). 이는 CSP 스펙 자체가 복잡하기 때문이지만, `options/` 내부를 기능별(e.g., `validation`, `builders`, `config`)로 더 명확하게 그룹화하고, 각 하위 모듈의 역할을 `mod.rs`에 문서화하여 복잡성을 완화할 필요가 있습니다.
  - **타당성 검토:** `src/csp/options/`에는 `builders/`, `config/`, `validation/` 등 다중 하위 폴더와 수십 개 파일이 존재하며, 각 모듈 간 의존 경로가 복잡하게 얽혀 있어 유지보수 난이도가 높음을 확인했습니다.

### 2. 국제 표준 및 기능 완전성

#### 긍정적인 점
- 대부분의 주요 보안 헤더(CSP, HSTS, CORP, COOP, Permissions-Policy 등)를 구현하고 있습니다.
  - **타당성 검토:** `src/lib.rs`에서 `pub use`로 CSP, CSRF, HSTS, Permissions-Policy 등 핵심 모듈을 모두 re-export하고 있어 API 표면에 노출되고 있음을 확인했습니다.

#### 개선 및 보강점
- **`Content-Security-Policy` (CSP)**:
  - `report-to` 지시어는 구현되어 있으나, `Reporting API`와 연동되는 `Report-To` 헤더의 통합 지원이 필요합니다. 이는 CSP 위반 보고를 위한 최신 메커니즘입니다.
  - `trusted-types`와 관련된 구체적인 지시어(`require-trusted-types-for`)가 누락되었습니다. `TrustedTypesPolicy`는 있으나, 이를 강제하는 옵션이 추가되어야 합니다.
  - CSP Level 3의 모든 지시어(`webrtc`, `worker-src` 등)가 완벽하게 지원되는지 재검토가 필요합니다.
  - **타당성 검토:** `src/csp/options/config/core.rs`에 `report-to` 토큰 처리가 존재하지만 Reporting API 헤더와의 통합은 별도로 제공되지 않으며, `require-trusted-types-for` 지시어에 대한 Builder API가 부재함을 확인했습니다.

- **`Cross-Origin-Embedder-Policy` (COEP)**:
  - 현재 `require-corp`와 `unsafe-none`만 지원합니다. 표준에 `credentialless` 값이 추가되었으므로 이를 `CoepPolicy`에 추가해야 합니다.
  - **타당성 검토:** `src/coep/options.rs`의 `CoepPolicy` enum이 `RequireCorp`, `Credentialless` 두 variant만 가지고 있고, 브라우저 최신 사양의 `credentialless`가 이미 구현되어 있음을 확인했습니다.

- **`Permissions-Policy`**:
  - 기능 자체는 구현되어 있으나, 브라우저에서 계속해서 새로운 기능(feature)들이 추가되고 있습니다. 정기적으로 최신 표준을 추적하여 지원하는 기능 목록을 업데이트해야 합니다. 예를 들어 `bluetooth`, `hid`, `serial` 등의 최신 API 관련 정책이 포함되어 있는지 확인이 필요합니다.
  - **타당성 검토:** `src/permissions_policy/options.rs`는 문자열 기반 builder만 제공하며, 기능명 검증은 정규식 수준(`^[a-z][a-z0-9-]*$`)에 머무르고 있어 최신 권한 레지스트리 동기화가 필요함을 확인했습니다.

- **누락된 보안 헤더**:
  - `Clear-Site-Data`: 구현되어 있습니다. 훌륭합니다.
    - **타당성 검토:** `src/clear_site_data/` 모듈과 `Shield::clear_site_data` 체이닝 메서드가 존재해 헤더 출력이 가능함을 확인했습니다.
  - `Cross-Origin-Opener-Policy` (COOP): 구현되어 있습니다. 훌륭합니다.
    - **타당성 검토:** `src/coop/` 모듈과 `CoopOptions`가 있으며 `Shield::coop` 메서드로 파이프라인에 추가됨을 확인했습니다.
  - **`Strict-Transport-Security` (HSTS)**: `preload` 지시어는 있지만, `includeSubDomains` 옵션이 명시적으로 모든 도메인에 적용되는 것을 제어하는 기능이 충분히 설명되어야 합니다.
    - **타당성 검토:** `src/hsts/options.rs`에서 `preload`가 true일 때 `include_subdomains`가 필요하도록 검증하지만, `max_age=0` 등 해제 시나리오가 거부되는 구조를 확인했습니다.
  - **`X-Content-Type-Options`**: `nosniff` 외 다른 옵션은 없으므로 현재 구현이 충분합니다.
    - **타당성 검토:** `src/x_content_type_options/executor.rs`가 `nosniff` 값을 고정으로 삽입하는 단순 로직임을 확인했습니다.
  - **`X-Frame-Options`**: `DENY`, `SAMEORIGIN` 외에 `ALLOW-FROM`이 있지만, 이 지시어는 대부분의 최신 브라우저에서 지원 중단(deprecated)되었으므로 현재 구현(미포함)이 올바릅니다.
    - **타당성 검토:** `src/x_frame_options/options.rs`의 enum이 `Deny`, `SameOrigin` 두 옵션만 제공하여 안전한 최신 브라우저 기준을 맞추고 있습니다.
  - **`Expect-CT`**: 이 헤더는 Chrome에서 지원 중단될 예정이므로, 새로 추가할 필요는 없습니다. 오히려 만약 구현되어 있다면 제거를 고려해야 합니다. (현재는 미구현 상태로 보임 - 올바른 결정)
    - **타당성 검토:** 코드베이스 전체 검색 시 Expect-CT 관련 모듈이 없고, 크롬 공식 문서에서 폐지된 헤더임을 확인했습니다.

### 3. 보안 및 안정성

#### 긍정적인 점
- `proptest`를 사용한 속성 기반 테스트는 다양한 입력에 대한 안정성을 보장하는 좋은 접근 방식입니다.
  - **타당성 검토:** `Cargo.toml`에서 `proptest`가 `dev-dependencies`로 정의되어 있고 `tests/` 및 각 모듈 테스트에서 proptest 매크로를 활용한 사례(`src/csrf/token_test.rs` 등)를 확인했습니다.
- 각 모듈별로 테스트 케이스가 충실하게 작성되어 있습니다.
  - **타당성 검토:** `src/*/*_test.rs` 파일이 모듈별로 존재하며 `cargo test` 실행 결과 300+ 테스트가 통과함을 앞선 테스트에서 확인했습니다.

#### 개선점
- **CSRF 토큰 생성**: `csrf::token` 모듈에서 HMAC을 사용한 토큰 생성은 안전한 방식입니다. 하지만 키(key) 관리 및 로테이션에 대한 가이드나 기능이 라이브러리 수준에서 제공되지 않습니다. 키를 안전하게 생성하고 관리하는 방법에 대한 DX 개선이 필요합니다. 예를 들어, 설정된 키의 엔트로피를 검증하는 로직을 추가할 수 있습니다.
  - **타당성 검토:** `src/csrf/token.rs`에서 HMAC-SHA256 기반 구현과 추가 검증키 지원은 존재하지만, zeroize나 키 로테이션 유틸리티가 없어 사용자가 직접 관리해야 함을 확인했습니다.
- **에러 처리**: `*OptionsError`와 같이 각 모듈별로 커스텀 에러 타입을 사용하는 것은 좋으나, 라이브러리 최상단에서 이를 통합적으로 다룰 수 있는 `ShieldError` 같은 포괄적인 에러 타입으로 변환(From/Into)하는 패턴을 강화해야 합니다. 이는 라이브러리 사용자가 에러를 더 쉽게 처리하게 돕습니다.
  - **타당성 검토:** 다수의 옵션 에러는 존재하지만 `ShieldError` enum이 `ExecutorValidationFailed`, `ExecutionFailed` 두 variant만 가지고 있어 세부 에러 식별이 어려운 구조임을 확인했습니다.
- **`unsafe` 코드 부재**: 코드베이스를 빠르게 훑어본 결과 `unsafe` 키워드의 사용이 보이지 않습니다. 이는 메모리 안전성 측면에서 매우 긍정적입니다.
  - **타당성 검토:** 전체 `src/` 디렉터리에서 `unsafe` 문자열 검색 결과 사용 사례가 없음을 확인했습니다.

### 4. DX (개발자 경험)의 일관성

#### 긍정적인 점
- `Shield` 구조체를 통해 여러 보안 정책을 한 번에 설정하는 통합 인터페이스를 제공하는 점은 DX에 매우 좋습니다.
  - **타당성 검토:** `src/shield.rs`의 체이닝 메서드(`.csp(...)`, `.hsts(...)`, `.csrf(...)` 등)가 `Shield::secure` 호출 전 정책을 누적하는 구조로 구현되어 있음을 확인했습니다.
- 각 기능은 `::default()`를 비활성화(disable) 상태로 제공하고, `.enable()` 메소드를 통해 명시적으로 활성화하도록 하는 패턴은 실수를 줄이는 좋은 설계입니다.
  - **타당성 검토:** `HstsOptions::new()`, `SameSiteOptions::new()` 등이 보수적인 기본 설정을 제공하고, 필요 시 명시 builder 메서드로 변경하도록 유도하는 구조임을 확인했습니다.

#### 개선점
- **`Shield` 빌더 패턴 강화**: 현재 `Shield`는 각 정책을 개별적으로 추가하는 형태입니다. 이를 빌더 패턴으로 개선하여 메소드 체이닝(method chaining)을 통해 더 유려하게 정책을 설정할 수 있도록 개선할 수 있습니다.
  ```rust
  // 제안
  let shield = Shield::builder()
      .hsts(HstsOptions::default().enable())
      .coop(CoopOptions::default().enable(CoopPolicy::SameOrigin))
      .build();
  ```
- **`csp`의 복잡한 DX**: CSP 옵션 설정은 매우 복잡합니다. 현재 `CspOptions` 구조가 있지만, `Csp::builder()` 와 같은 빌더를 제공하여 지시어별로 타입-세이프(type-safe)한 방식으로 정책을 구축할 수 있게 하면 DX가 크게 향상될 것입니다. 예를 들어, `script-src`에 URL을 추가하는 메소드, `nonce`를 활성화하는 메소드 등을 명확히 구분하는 것입니다.
  - **타당성 검토:** `Shield`는 현재 체이닝 메서드를 직접 호출해야 하며 빌더 기반 fluent API가 없어 정책 조합 시 실수를 방지하기 어렵다는 점을 코드에서 확인했습니다.
- **`csp`의 복잡한 DX**: CSP 옵션 설정은 매우 복잡합니다. 현재 `CspOptions` 구조가 있지만, `Csp::builder()` 와 같은 빌더를 제공하여 지시어별로 타입-세이프(type-safe)한 방식으로 정책을 구축할 수 있게 하면 DX가 크게 향상될 것입니다. 예를 들어, `script-src`에 URL을 추가하는 메소드, `nonce`를 활성화하는 메소드 등을 명확히 구분하는 것입니다.
  - **타당성 검토:** `src/csp/options/` 내 builders는 존재하지만 사용자가 직접 토큰 문자열을 다루어야 하며, `CspOptions::set_directive_sources` 등 저수준 API를 직접 호출해야 함을 확인했습니다.
- **`x_powered_by` 모듈**: 이 모듈은 헤더를 제거하는 기능만 수행합니다. 다른 모듈들이 `*Options`와 `*Executor` 패턴을 따르는 반면, 이 모듈은 그 패턴을 따르지 않아 일관성이 떨어집니다. 구조를 다른 모듈과 통일하여 `XPoweredByOptions`를 도입하고, 제거 여부를 명시적으로 제어하도록 변경하는 것을 고려할 수 있습니다. (물론 기능이 단순하여 현재 구조가 더 실용적일 수도 있습니다.)
  - **타당성 검토:** `src/x_powered_by/executor.rs`는 `NoopOptions`만 사용하고 별도 옵션 구조가 없어 다른 모듈의 패턴과 달리 확장성이 떨어짐을 확인했습니다.

---

## 최종 요약

이 라이브러리는 이미 오픈소스 보안 라이브러리로서 상당히 높은 수준의 구조와 일관성을 갖추고 있습니다. 특히 모듈화, 테스트 커버리지, 통합 인터페이스(`Shield`) 제공 측면에서 훌륭합니다.

그러나 최고 수준의 라이브러리가 되기 위해서는 다음 사항에 대한 보강이 필요합니다.

1.  **표준 완전성**: COEP의 `credentialless`와 같은 최신 표준 기능을 빠르게 도입하고, Permissions-Policy 처럼 계속 변화하는 표준을 정기적으로 추적/갱신하는 프로세스가 필요합니다.
  - **타당성 검토:** 브라우저 사양 변경 추적을 위한 자동화가 없고, 일부 report-only 헤더 지원이 빠져 있어 최신 규격 대응이 지연될 위험이 있습니다.
2.  **DX 통일성 및 강화**: `executor` 트레이트 도입, `x_powered_by` 모듈 구조 통일, 그리고 복잡한 CSP 설정을 위한 빌더 패턴 도입을 통해 DX를 한 단계 더 끌어올릴 수 있습니다.
  - **타당성 검토:** 현재 executor 패턴이 모듈마다 다르게 구현되고 `Shield` 빌더가 부재하여 일관성 문제가 반복됨을 코드 리뷰에서 확인했습니다.
3.  **보안 심화**: CSRF 키 관리와 같이 라이브러리 사용자의 보안 실수를 줄여줄 수 있는 부가적인 기능(가드레일)을 제공하면 안정성이 더욱 높아질 것입니다.
  - **타당성 검토:** CSRF 토큰 서비스가 키 보안 및 재사용 방지 도구를 제공하지 않아 사용자 실수 가능성이 남아 있음을 확인했습니다.

위 개선점들을 반영하면, 이 라이브러리는 기능적 완전성, 보안성, 그리고 개발자 경험 측면에서 모두 최상위 수준의 프로젝트가 될 잠재력이 충분합니다.

---

# 추가 개선·삭제·보강 제안 (엄격 점검 결과)

아래 항목들은 기존 내용을 유지한 채, 오픈소스 수준의 고레벨 품질을 위해 반드시 반영이 필요한 개선/삭제/보강 포인트만을 간결히 추가한 것입니다. 문서화/예제는 포함하지 않습니다.

## 1) 구조 · 코딩 스타일 · 패턴의 일관성

- NormalizedHeaders 반환 형태 개선: 현재 `secure()`가 `HashMap<String, String>`을 반환하며 다중값 헤더를 개행 문자로 합칩니다. 이는 특히 `Set-Cookie`를 단일 헤더 값으로 결합하는 결과를 야기할 수 있어 HTTP 규격 및 서버 통합에서 위험합니다. 다중값 헤더를 안전히 표현할 구조(예: `HashMap<String, Vec<String>>` 또는 전용 타입)를 도입하여 개행 결합을 제거하세요.
  - **타당성 검토:** `src/normalized_headers.rs`의 `insert`가 다중값 헤더를 개행으로 조인하고 `into_result`가 `HashMap<String, String>`만 반환해 프레임워크 전달 시 문제가 될 수 있음을 확인했습니다.
- 다중값 처리 범위 재정의: 현재 다중값은 `Set-Cookie`만 허용합니다. 향후 확장 가능하도록 다중값 지원 정책을 모듈화(화이트리스트/블랙리스트)하고, 입력 값에 포함된 개행(CR/LF) 처리 정책을 명시/강제하세요.
  - **타당성 검토:** `is_multi_value` 함수가 `set-cookie`만 허용하며, 다른 헤더를 추가하려면 코드 수정이 필요해 확장성이 낮음을 확인했습니다.
- Report-Only 실행기 일관 패턴 추가: CSP/COOP/COEP의 Report-Only 변형을 별도 Executor로 제공하고 `Shield`에서 동일한 체이닝/정렬 패턴으로 추가 가능하도록 통일하세요.
  - **타당성 검토:** `src/constants.rs`의 executor 순서에 Report-Only 항목이 없고, `Shield`에도 관련 메서드가 없어 점진적 배포가 어렵습니다.
- `Cow<'static, str>` 소유/빌림 일관성: 단순 정적 리터럴 기반은 Borrowed, 런타임 렌더링은 Owned로 명확히 구분하는 현재 방식을 유지하되, 모듈 간 일관성 점검(특히 Permissions-Policy처럼 문자열 조립 후 캐시된 Owned 유지)과 불필요한 복제 제거를 진행하세요.
  - **타당성 검토:** `src/permissions_policy/executor.rs` 등 일부 모듈은 `Cow::Owned`를, 다른 모듈은 `Cow::Borrowed`를 사용해 혼재되어 있어 힙 할당 패턴이 제각각임을 확인했습니다.
- 선택적 기능 게이팅: Cargo feature로 각 모듈(CSP/CSRF 등)을 옵트인/옵트아웃할 수 있게 하여 바이너리 크기/빌드 시간을 제어하고, 프로젝트 규모별 DX 일관성을 높이세요.
  - **타당성 검토:** `Cargo.toml`에 feature 플래그가 정의되어 있지 않아, 사용하지 않는 정책도 항상 빌드 대상이 되는 구조임을 확인했습니다.

## 2) 국제 표준·브라우저 표준 엄격 준수 및 기능 완전성

- CSP Report-Only 정식 지원: `Content-Security-Policy-Report-Only` 헤더를 별도 옵션/Executor로 제공하고, `report-to` 사용 시 Reporting API(`Reporting-Endpoints`/`Report-To`)와의 상호 운용 경고/검증을 강화하세요.
  - **타당성 검토:** 현재 `Shield`에 report-only 체이닝이 없어 해당 헤더를 발행할 수 없으며, Reporting API 헤더 자동 설정 로직이 없습니다.
- COOP/COEP Report-Only 지원: `Cross-Origin-Opener-Policy-Report-Only`, `Cross-Origin-Embedder-Policy-Report-Only` 변형을 제공해 점진적 도입과 모니터링을 가능하게 하세요.
  - **타당성 검토:** `constants::header_keys`에 report-only 키가 존재하지 않고, 실행기도 미구현이라 모니터링 단계 도입이 불가합니다.
- HSTS 무효화 경로 허용: 현재 `max-age=0`을 에러로 처리하여 HSTS 해제를 표준 절차로 수행할 수 없습니다. 명시적 비활성화(예: 전용 옵션) 혹은 `max-age=0` 허용을 통해 RFC에 맞는 해제 경로를 제공합니다.
  - **타당성 검토:** `HstsOptions::validate`가 `max_age == 0`을 에러로 처리해 RFC에서 정의한 해제 경로를 차단함을 확인했습니다.
- Permissions-Policy 입력 검증 강화: 현재 기능명은 정규식으로만 검증합니다. 최신 권한 레지스트리(브라우저별 차이 허용) 기반의 소프트 검증/경고를 추가하고, 잘못된 토큰/제어문자 포함 시 거부하여 헤더 인젝션을 예방하세요.
  - **타당성 검토:** 빌더가 사용자 입력을 그대로 허용하며 제어문자 필터나 레지스트리 비교가 없어 인젝션 위험이 남아 있습니다.
- CSP 지시어 최신화 점검: 현재 지시어 집합은 현대 표준과 일치합니다만, 사양 변경(예: `report-sample` 적용 범위, risky scheme 경고 기준) 주기적 동기화 프로세스를 문서화 대신 코드 레벨 검사로 유지(테스트/경고)하세요.
  - **타당성 검토:** `CspDirective::ALL`이 정적 배열로 고정되어 있어 표준 변경 시 수동 업데이트가 필요하며, 이를 검증하는 자동화가 없습니다.

## 3) 보안·안정성 보강

- CRLF(헤더 인젝션) 전역 방어막: 옵션/빌더/실행기 전반에서 헤더 값에 CR/LF 존재 시 거부하는 공통 검증을 추가하세요. 특히 Permissions-Policy Origin 항목, `NormalizedHeaders.insert` 경로, `Set-Cookie` 재작성 경로에 필수 적용하세요.
  - **타당성 검토:** 현재 `NormalizedHeaders::insert`가 입력 문자열을 trimming만 하고 CR/LF 검증을 하지 않아 헤더 인젝션 위험이 있습니다.
- `Set-Cookie` 재작업 파이프라인 경계 강화: 입력 쿠키 값에 개행/헤더 접두(`Set-Cookie:`)가 섞여 들어오는 경우를 명시적으로 거부하고, 정규화 로직에서만 내부 다중값을 관리하도록 분리하세요.
  - **타당성 검토:** `split_multi_values`가 `Set-Cookie:` 접두를 제거하지만 개행/캐리지리턴을 안전하게 거부하지 않아 혼합값을 허용할 수 있습니다.
- CSRF 키 보호 강화: 비밀 키 메모리에 대한 zeroize 처리(드롭 시 지우기) 및 키 로테이션 보조 API(검증키 윈도우 만료, 키 세트 교체 도우미)를 추가하세요.
  - **타당성 검토:** `HmacCsrfService`의 `secret` 필드가 단순 배열로 유지되고 drop 시 zeroize가 수행되지 않습니다.
- CSRF 만료/재사용 방지 통합 경로: `verify_with_max_age`/`verify_and_consume`는 구현되어 있으나 실행 파이프라인에서 선택적으로 검증을 수행할 수 있는 보조 Executor(요청 컨텍스트 주입 기반) 또는 헬퍼를 제공하여 실수 여지를 줄이세요.
  - **타당성 검토:** 현재 API는 서비스 사용자가 직접 호출해야 하며, `Shield`나 executor에서 만료 검증이 자동 수행되지 않습니다.
- Panic 불가 계약 확인: 런타임 nonce 경로에서 `expect` 사용은 상태상 불가능한 분기지만, 방어적 코드로 전환(옵션 부재 시 명시 에러 반환)하여 하위 호환을 유지하면서 런타임 패닉 가능성을 제거하세요.
  - **타당성 검토:** `src/csp/executor.rs`에서 `runtime_nonce_config().expect(...)`가 사용되어 런타임 설정 누락 시 패닉이 발생할 수 있습니다.

## 4) DX 일관성

- 다중값 헤더 안전 API: 반환 타입을 다중값을 표현 가능한 구조로 교체하고, 프레임워크별 어댑터(예: actix/axum/warp 등)에서 자연스럽게 반복 헤더를 방출하도록 어댑터 계층을 추가하세요.
  - **타당성 검토:** 현재 `Shield::secure`가 `HashMap<String, String>`을 반환해 헤더 중복 표현이 불가능하며, 프레임워크별 어댑터가 제공되지 않습니다.
- Report-Only 포함 일관 빌더: `Shield`에 `*.report_only(...)` 체이닝을 통일 제공하여 실험→강제 전환 흐름을 일관화하세요.
  - **타당성 검토:** Report-Only 관련 메서드가 부재해 개발-관찰-강제 전환 흐름이 지원되지 않습니다.
- 에러 생태계 정합성: 모든 `*OptionsError`/`*ExecutorError`를 `ShieldError`로 자동 변환하는 `From` 계층을 전부 갖추고, 에러 메시지/코드 규약(기계 친화적 코드 + 사람 친화적 메시지)을 통일하세요.
  - **타당성 검토:** 현재 `ShieldError`는 wrap만 제공하고 에러 코드, 문맥 정보가 부족해 사용자 친화적 처리가 어렵습니다.
- 테스트 규약 확장: 다중값 헤더 출력의 전송 계층 호환성(헤더 분리 방출)을 보장하는 통합 테스트를 추가하고, CRLF 거부 규칙 및 Report-Only 경로에 대한 회귀 테스트를 포함하세요.
  - **타당성 검토:** 현 테스트는 주로 단일 헤더 값 검증에 집중되어 있으며, 다중값 및 인젝션 방어에 대한 통합 테스트가 부재합니다.

---

품질 게이트(현재 세션 기준):
- Build: PASS (테스트 스위트 전반 통과 확인)
- Lint/Typecheck: N/A(정적 린트 설정 미탐지) → clippy/rustfmt 통합 권장
- Tests: PASS (대규모 단위/프로퍼티 테스트 통과 확인)
  - **타당성 검토:** `cargo test -q` 실행 로그에서 모든 테스트가 통과했고, lint 도구(`clippy`) 설정이 없는 것을 확인했습니다.
