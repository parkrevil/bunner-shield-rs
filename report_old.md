# bunner-shield-rs 보안 라이브러리 분석 보고서

이 보고서는 `bunner-shield-rs` 라이브러리의 코드베이스를 분석하여 개선이 필요하거나 부적합한 사항들을 정리합니다.

## 분석 요약

(분석이 진행됨에 따라 내용이 추가될 예정입니다.)

## 1. 프로젝트 설정

### 1.1. 유효하지 않은 Rust 에디션 사용

`Cargo.toml` 파일에 `edition = "2024"`로 명시되어 있습니다. 현재 Rust의 안정 버전 에디션은 `2021`이 최신이며, `2024` 에디션은 존재하지 않아 빌드 오류를 유발합니다. 프로젝트의 안정성과 호환성을 위해 `2021`로 수정해야 합니다.

## 2. 국제 표준 및 브라우저 표준 준수

### 2.1. HSTS (HTTP Strict Transport Security)

#### 2.1.1. `preload` 옵션의 `max-age` 기본값 미준수

HSTS `preload` 옵션을 사용할 경우, `hstspreload.org`에서는 `max-age`를 최소 2년(63,072,000초)으로 설정할 것을 권장하고 있습니다. 하지만 현재 라이브러리의 기본값은 1년(31,536,000초)으로 설정되어 있습니다. `preload` 옵션 활성화 시 기본적으로 권장 사항을 충족하도록 `max-age` 기본값을 2년으로 상향 조정해야 합니다.

### 2.2. CSP (Content Security Policy)

#### 2.2.1. 일부 CSP 지시어 누락

MDN의 최신 `Content-Security-Policy` 명세와 비교했을 때, 아래 지시어들이 누락되어 있습니다.

- **`child-src`**: `frame-src`와 `worker-src`의 대체(fallback) 역할을 하는 지시어입니다. 명세에 포함된 표준 지시어이므로 추가하는 것이 좋습니다.
- **`report-uri`**: `report-to` 지시어로 대체되었지만, 구형 브라우저 호환성을 위해 여전히 유용합니다. MDN에서는 `report-to`가 널리 지원될 때까지 두 지시어를 함께 사용하도록 권장하고 있습니다. 따라서 하위 호환성을 위해 지원을 추가하는 것을 고려해야 합니다.
- **`fenced-frame-src`**: 현재 실험적인 기능이지만, 향후 표준으로 채택될 가능성이 있으므로 추후 지원을 검토할 수 있습니다.

#### 2.2.2. CSP `child-src` 지시어 누락

MDN의 CSP 명세에 따르면 `child-src` 지시어는 `frame-src`와 `worker-src`의 fallback으로 동작하는 표준 지시어입니다. 하지만 `src/csp/options/types.rs`의 `CspDirective` 열거형에 `ChildSrc`가 누락되어 있어 사용자가 이 지시어를 설정할 수 없습니다.

#### 2.2.3. `block-all-mixed-content` 지시어 사용

`block-all-mixed-content` 지시어는 CSP Level 3부터 `upgrade-insecure-requests` 지시어로 대체되어 deprecated 되었습니다. 현재 라이브러리에 포함되어 있지만, deprecated 되었다는 사실을 명시하고 `upgrade-insecure-requests` 사용을 권장해야 합니다.

### 2.3. Referrer-Policy

#### 2.3.1. 다중 정책(Fallback) 미지원

MDN 문서에 따르면, `Referrer-Policy` 헤더는 쉼표로 구분하여 여러 정책을 명시할 수 있습니다. 이는 브라우저가 지원하지 않는 정책에 대한 대체(fallback) 정책을 제공하기 위함입니다. 예를 들어, `Referrer-Policy: no-referrer, strict-origin-when-cross-origin`과 같이 설정하면 `strict-origin-when-cross-origin`을 지원하지 않는 브라우저에서는 `no-referrer`가 적용됩니다.

현재 라이브러리는 단일 정책만 설정할 수 있도록 구현되어 있어, 이러한 fallback 기능을 지원하지 않습니다. 다양한 브라우저 환경에 대한 호환성을 높이기 위해 다중 정책 설정을 지원하는 것이 바람직합니다.

## 3. 기능적 가치 및 디자인 패턴

### 3.1. CSRF (Cross-Site Request Forgery) 방어

#### 3.1.1. CSRF 토큰 검증 로직의 부분적 구현

현재 CSRF 방어 기능은 "Double Submit Cookie" 패턴을 구현하고 있습니다. `HmacCsrfService`는 토큰 발급(`issue`)과 검증(`verify`, `verify_with_max_age`, `verify_and_consume`) 메서드를 모두 제공하고 있습니다.

**하지만**, `src/csrf/executor.rs`의 `Csrf` executor는 **토큰 발급만 수행하고, 실제로 수신된 요청에서 토큰을 검증하는 로직이 전혀 없습니다**. `execute` 메서드는 새로운 토큰을 생성하여 응답 헤더와 쿠키에 추가하는 것만 합니다.

```rust
// src/csrf/executor.rs의 execute 메서드는 토큰 발급만 수행
let token = self.token_service.issue(self.options.token_length)?;
headers.insert_owned(CSRF_TOKEN, token);
headers.insert_owned(SET_COOKIE, cookie);
```

이는 다음과 같은 치명적인 문제를 야기합니다:

1. **완전히 무방비**: 토큰을 발급하기만 하고 검증하지 않으므로 CSRF 공격을 전혀 방어할 수 없습니다.
2. **미들웨어 통합 부재**: 일반적인 CSRF 방어는 두 단계로 구성됩니다:
   - GET 요청: 토큰 발급
   - POST/PUT/DELETE 요청: 토큰 검증
   
   현재 구현은 첫 번째 단계만 있고, 두 번째 단계가 완전히 누락되어 있습니다.

3. **API 설계 불완전**: 라이브러리가 응답 헤더 설정에만 초점을 맞춰 설계되었기 때문에, 요청 헤더 검증 기능을 통합할 명확한 방법이 없습니다.

또한, `HmacCsrfService`의 검증 메서드들도 다음과 같은 문제가 있습니다:

- **`verify`**: 서명만 검증하고 만료 시간을 확인하지 않아, 탈취된 토큰이 영구적으로 유효합니다.
- **`verify_with_max_age`**: 만료 시간 검증을 제공하지만, 현재 시간(`now_secs`)을 매개변수로 받아야 해서 사용이 불편하고, 시스템 시간 조작에 취약할 수 있습니다.
- **`verify_and_consume`**: Replay Attack 방지를 위한 일회용 토큰 검증을 제공하지만, `CsrfReplayStore` 트레이트의 구현체가 라이브러리에 포함되어 있지 않아 사용자가 직접 구현해야 합니다.

#### 3.1.2. Origin/Referer 검증의 한계

`validate_origin` 함수는 요청의 `Origin` 또는 `Referer` 헤더를 검증하여 허용된 출처(origin)인지 확인합니다. 하지만 현재 구현은 `Host` 헤더를 기준으로 허용된 출처를 동적으로 생성하는데, 이는 다음과 같은 문제를 가집니다.

- **`Host` 헤더 위조**: `Host` 헤더는 클라이언트가 임의로 변경할 수 있으므로, 공격자가 `Host` 헤더를 위조하여 보내면 Origin 검증을 우회할 수 있습니다.
- **고정된 허용 목록 부재**: 일반적으로 CSRF 방어를 위한 Origin 검증은 사전에 정의된 안전한 출처 목록(allow-list)을 기반으로 수행되어야 합니다. 현재 구현처럼 요청 헤더에 의존하는 방식은 안전하지 않습니다.

따라서, `Host` 헤더 기반의 동적 출처 생성을 제거하고, 사용자가 명시적으로 안전한 출처 목록을 설정할 수 있도록 기능을 변경해야 합니다.

#### 3.1.3. Stateless Token의 비효율적인 상태 관리

`HmacCsrfService`는 `AtomicU64` 카운터를 사용하여 nonce를 생성하는데, 이는 서버가 재시작될 때마다 초기화됩니다. 이는 stateless를 지향하는 토큰 기반 시스템의 장점을 일부 상실하게 만듭니다. 또한, `verification_keys`를 `Vec`으로 관리하는 것은 키 로테이션을 염두에 둔 것으로 보이나, 현재 키를 추가하거나 제거하는 명확한 인터페이스가 없어 실용성이 떨어집니다.

## 4. 디자인 패턴 및 DX(Developer Experience)

### 4.1. 일관성 없는 모듈 구조 및 네이밍

대부분의 기능 모듈(예: `hsts`, `coep`, `coop`)은 `executor.rs`와 `options.rs`로 구성되어 있으며, `mod.rs`에서 이를 외부에 공개(export)하는 일관된 구조를 가집니다. 하지만 일부 모듈은 이러한 패턴을 따르지 않아 일관성을 해치고 있습니다.

- **`referrer_policy`**: `ReferrerPolicy`라는 이름의 `executor`가 이미 존재함에도 불구하고, `lib.rs`에서 `ReferrerPolicyExecutor`를 `ReferrerPolicy`로 리네이밍하여 사용하고 있습니다. 이는 혼란을 유발하며, 다른 모듈과의 일관성을 깨뜨립니다.
- **`csp`, `csrf`**: 다른 모듈과 달리 `options`가 하위 디렉토리로 분리되어 있습니다. 특히 `csp` 모듈은 `options` 디렉토리 안에 `builders`, `config`, `validation` 등 여러 하위 모듈을 포함하고 있어 구조가 복잡하고 다른 모듈과 형태가 다릅니다. 기능의 복잡성 때문일 수 있지만, 최상위 구조는 다른 모듈과 유사하게 맞추는 것이 DX 측면에서 좋습니다.

### 4.2. `Shield` 구조체의 빌더 패턴 복잡성

`Shield` 구조체는 빌더 패턴을 사용하여 각 보안 기능을 추가하도록 설계되었습니다. 하지만 각 기능 추가 메서드(예: `csp`, `hsts`)가 `self`를 반환하면서 `Result<Self, ShieldError>` 타입을 사용하여, 메서드 체이닝 시 `unwrap()` 이나 `?` 연산자를 강제합니다.

```rust
let shield = Shield::new()
    .csp(CspOptions::default())?
    .hsts(HstsOptions::default())?;
```

옵션 유효성 검사는 `Shield::new()`나 각 기능 추가 시점이 아닌, 실제 헤더를 처리하는 `secure()` 메서드 호출 시점에 수행하는 것이 더 효율적이고 DX에 유리합니다. 빌더 패턴을 사용하는 주된 이유 중 하나는 쉽고 깔끔한 객체 생성인데, 현재 구조는 이를 방해하고 있습니다.

### 4.3. 불필요한 `Executor` 추상화

`executor.rs`에는 `FeatureExecutor`, `DynFeatureExecutor` 트레이트와 `CachedHeader`, `DynamicHeaderCache` 등 다양한 추상화가 존재합니다. 하지만 대부분의 기능은 단순히 미리 계산된(또는 정적인) 헤더 값을 설정하는 역할만 합니다. 예를 들어, `Hsts`, `Coop`, `Corp` 등은 `CachedHeader`를 사용하여 생성 시점에 헤더 값을 계산하고, `execute` 시점에는 단순히 저장된 값을 헤더에 추가합니다.

이러한 과도한 추상화는 다음과 같은 단점이 있습니다.

- **코드 복잡성 증가**: 간단한 기능을 위해 여러 트레이트와 구조체를 거쳐야 하므로 코드 이해가 어렵습니다.
- **유지보수 비용 증가**: 새로운 기능을 추가할 때 불필요한 보일러플레이트 코드를 작성해야 합니다.
- **성능 저하 가능성**: `Box<dyn ...>`을 사용한 동적 디스패치는 정적 디스패치에 비해 약간의 런타임 오버헤드를 유발할 수 있습니다.

대부분의 기능은 간단한 함수나 작은 구조체로 충분히 구현할 수 있으며, `Shield` 구조체는 `Vec<Box<dyn ...>>` 대신 각 기능의 구체적인 타입을 직접 관리하는 것이 더 명확하고 효율적일 수 있습니다.

### 4.4. `lib.rs`의 과도한 `pub use`

`lib.rs` 파일은 라이브러리의 최상위 API를 구성하는 역할을 합니다. 하지만 현재 파일은 각 모듈의 거의 모든 타입을 `pub use`로 외부에 공개하고 있습니다. 이는 사용자가 실제로 필요하지 않은 내부 구현 세부사항까지 노출시켜 API를 복잡하게 만들고, 라이브러리의 주된 목적인 "간편한 보안 헤더 설정"을 방해합니다.

예를 들어, `CspNonceManagerError`, `FetchMetadataParseError` 등은 특정 기능의 세부 오류 타입으로, 최상위 레벨에 노출될 필요가 없습니다. API를 간결하게 유지하고 사용자가 핵심 기능에 집중할 수 있도록, 필수적인 타입(예: `Shield`, 각 기능의 `Options` 구조체)만 외부에 공개하고 나머지는 모듈 경로를 통해 접근하도록 하는 것이 좋습니다.

### 4.5. Permissions-Policy

#### 4.5.1. 잘못된 Allowlist 직렬화

`Permissions-Policy` 헤더의 명세에 따르면, 허용 목록(allowlist)에 포함되는 출처(origin)는 큰따옴표(`"`)로 묶여야 합니다. 예를 들어, `geolocation=(self "https://example.com")`과 같은 형태가 올바른 형식입니다.

하지만 현재 `PolicyBuilder` 구현(`src/permissions_policy/options.rs`)은 `AllowListItem::Origin`에 전달된 문자열을 그대로 사용하여 정책을 생성합니다. 이로 인해 사용자가 직접 따옴표를 추가하지 않으면 잘못된 헤더 값이 생성됩니다. 빌더 패턴의 목적은 사용자 편의성 향상이므로, 빌더 내부에서 자동으로 따옴표를 추가해야 합니다.

#### 4.5.2. `Feature-Policy` 헤더의 부정확한 사용

`Permissions-Policy`는 구형 `Feature-Policy` 헤더를 대체합니다. 현재 라이브러리는 `report_only` 모드에서 `Feature-Policy` 헤더를 함께 보내는 로직(`emit_feature_policy_fallback`)을 포함하고 있습니다.

하지만 `Feature-Policy`는 `Permissions-Policy-Report-Only`와 같은 보고 전용 헤더가 표준으로 존재하지 않았습니다. `Feature-Policy`의 위반 보고는 `report-to` 지시어를 통해 이루어졌습니다. 따라서 `Permissions-Policy-Report-Only` 헤더의 값을 `Feature-Policy` 헤더 값으로 그대로 사용하는 것은 표준에 부합하지 않으며, 브라우저에 따라 예기치 않은 동작을 유발할 수 있습니다.

### 4.6. Fetch Metadata

#### 4.6.1. 핵심 기능 누락: 요청 헤더 검증 로직 부재

`Sec-Fetch-*` 요청 헤더(Fetch Metadata)는 서버가 수신한 요청의 출처와 맥락을 검증하여 보안 결정을 내리도록 돕는 메커니즘입니다. 예를 들어, 특정 리소스는 `Sec-Fetch-Dest: document`가 아닌 요청(예: `script`, `image`)을 거부하여 직접 접근을 막을 수 있습니다.

하지만 현재 `FetchMetadata` executor(`src/fetch_metadata/executor.rs`)는 요청 헤더를 검증하는 대신, **응답 헤더에 `Vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site`를 추가**하는 역할만 수행합니다. `Vary` 헤더는 캐싱과 관련된 헤더로, 동일한 URL이라도 `Sec-Fetch-*` 헤더 값에 따라 다른 응답이 캐시되어야 함을 CDN이나 브라우저에 알리는 역할을 합니다. 이는 Fetch Metadata의 보조 기능일 뿐, 핵심적인 보안 검증 기능이 아닙니다.

실질적인 보안 가치를 제공하기 위해서는, 사용자가 정의한 규칙(예: "이 엔드포인트는 `Sec-Fetch-Site: same-origin`일 때만 허용")에 따라 수신된 요청 헤더를 검증하고, 규칙 위반 시 요청을 거부하는 로직이 반드시 포함되어야 합니다. 현재 구현은 이름과 달리 실제 보안 검증 기능이 누락되어 있어 **기능적 가치가 거의 없습니다**.

### 4.7. Cross-Origin 관련 헤더 (COEP, COOP, CORP)

#### 4.7.1. COEP (Cross-Origin-Embedder-Policy)

`src/coep/options.rs`를 검토한 결과, 표준에서 정의한 두 가지 정책 값(`require-corp`, `credentialless`)을 모두 지원하며, `report-only` 모드도 올바르게 구현되어 있습니다. 특별한 문제점은 발견되지 않았습니다.

#### 4.7.2. COOP (Cross-Origin-Opener-Policy)

`src/coop/options.rs`를 검토한 결과, 표준에서 정의한 세 가지 정책 값(`same-origin`, `same-origin-allow-popups`, `unsafe-none`)을 모두 지원하며, `report-only` 모드도 올바르게 구현되어 있습니다. 특별한 문제점은 발견되지 않았습니다.

#### 4.7.3. CORP (Cross-Origin-Resource-Policy)

`src/corp/options.rs`를 검토한 결과, 표준에서 정의한 세 가지 정책 값(`same-origin`, `same-site`, `cross-origin`)을 모두 지원하고 있습니다. 다만, CORP는 `report-only` 모드를 지원하지 않는데, 이는 표준에 부합합니다. 특별한 문제점은 발견되지 않았습니다.

### 4.8. SameSite Cookie 설정

#### 4.8.1. 응답 헤더 라이브러리에서의 쿠키 속성 수정 기능

`src/same_site/executor.rs`를 검토한 결과, 이 모듈은 `Set-Cookie` 헤더를 읽어서 `SameSite`, `Secure`, `HttpOnly` 속성을 추가하거나 덮어쓰는 방식으로 동작합니다. 

**기능 자체는 올바르게 구현**되어 있습니다:
- 기존 쿠키 값을 파싱하여 중복된 속성을 제거하고
- 사용자가 설정한 정책에 따라 `SameSite`, `Secure`, `HttpOnly` 속성을 추가합니다
- `SameSite=None`일 때 `Secure`가 필수인 것을 검증합니다

이는 다른 미들웨어나 프레임워크에서 설정한 쿠키에 보안 속성을 강제하는 유용한 기능입니다. 하지만 다음과 같은 개선점이 있습니다:

- **선택적 적용**: 모든 쿠키에 동일한 정책을 적용하는데, 쿠키 이름별로 다른 정책을 적용하는 기능이 없습니다.
- **Path, Domain 등 다른 속성**: 현재는 `SameSite`, `Secure`, `HttpOnly`만 처리하는데, `Path`, `Domain`, `Max-Age`, `Expires` 등의 속성도 필요에 따라 검증하거나 강제할 수 있으면 더 유용할 것입니다.

### 4.9. SafeHeaders 기능

#### 4.9.1. 기능의 모호성 및 문서화 부족

`src/safe_headers/executor.rs`를 검토한 결과, 이 기능은 `NormalizedHeaders::sanitize_for_http()` 메서드를 호출하여 헤더를 "정화(sanitize)"하는 역할을 합니다. `sanitize_for_http()` 메서드는 헤더 이름과 값에서 제어 문자를 제거하고, 유효하지 않은 헤더를 삭제합니다.

이는 HTTP Response Splitting 공격 등을 방지하는 중요한 보안 기능입니다. 하지만 다음과 같은 문제점이 있습니다.

- **기능 이름의 모호성**: `SafeHeaders`라는 이름만으로는 이 기능이 정확히 무엇을 하는지 명확하지 않습니다. `HeaderSanitizer`나 `HttpHeaderValidator` 같은 이름이 더 명확할 수 있습니다.
- **문서화 부족**: 이 기능이 어떤 보안 위협을 방지하는지, 어떤 경우에 헤더가 제거되는지에 대한 문서나 주석이 전혀 없습니다.
- **항상 활성화**: `Shield::default()`에서 이 기능이 기본적으로 활성화되는데, 사용자가 이 기능의 존재조차 인지하지 못할 수 있습니다.

보안 라이브러리에서 "보이지 않는" 기능은 신뢰성을 떨어뜨릴 수 있으므로, 이 기능에 대한 명확한 설명과 문서화가 필요합니다.

### 4.10. NormalizedHeaders 구조체

#### 4.10.1. Set-Cookie 헤더의 특수 처리 불완전

`src/normalized_headers.rs`를 검토한 결과, `Set-Cookie` 헤더를 다중 값(multi-value) 헤더로 처리하는 로직이 있습니다. HTTP 명세에 따르면 `Set-Cookie`는 여러 개의 헤더로 전송될 수 있으며, 이들은 병합되지 않아야 합니다.

현재 구현은 `is_multi_value()` 함수에서 `set-cookie`만을 특별히 처리하고 있습니다. 하지만 `into_result()` 메서드에서 모든 값을 `joined` 필드(`\n`으로 연결된 문자열)로 변환하여 반환합니다. 이는 다음과 같은 문제를 유발할 수 있습니다.

- **단일 헤더로 병합**: 여러 `Set-Cookie` 헤더가 하나의 헤더로 병합되어 반환될 수 있습니다.
- **HTTP 명세 위반**: RFC 7230에 따르면 `Set-Cookie` 헤더는 쉼표나 다른 구분자로 병합해서는 안 됩니다.

`into_result()` 메서드는 `Set-Cookie` 같은 다중 값 헤더를 `Vec<String>`으로 반환하거나, 각 값을 별도의 키-값 쌍으로 반환해야 합니다. 현재 구조는 `HashMap<String, String>`을 반환하므로 이를 개선하기 위해서는 API 변경이 필요합니다.

## 5. 추가 발견 사항

### 5.1. CSP 추가 모듈 검토 결과

#### 5.1.1. CSP Sources 구현 (`src/csp/options/sources.rs`)

`CspSource` 열거형은 CSP 소스 표현식을 구현하고 있습니다. 검토 결과 다음과 같은 특징이 있습니다:

- **지원 키워드**: `'self'`, `'none'`, `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`, `'wasm-unsafe-eval'`, `'strict-dynamic'`, `'report-sample'` 등 모든 표준 키워드를 지원합니다.
- **Nonce 및 Hash**: `'nonce-{value}'`와 `'sha256-{value}'` 형식을 올바르게 지원합니다.
- **입력 정화(Sanitization)**: `sanitize_token_input()` 함수를 사용하여 nonce와 hash 값을 정화하지만, 이 함수의 동작이 충분한지 확인 필요합니다.

#### 5.1.2. CSP Sandbox 토큰 (`src/csp/options/sandbox.rs`)

`SandboxToken` 열거형은 15개의 sandbox 토큰을 지원합니다:
- `allow-downloads`, `allow-forms`, `allow-modals` 등 표준 토큰을 모두 포함
- 최신 토큰인 `allow-downloads-without-user-activation`(2021년 추가)도 지원
- `FromStr` 트레이트 구현으로 문자열 파싱 가능

**문제점**: 없음. 표준 준수가 잘 되어 있습니다.

#### 5.1.3. CSP Trusted Types (`src/csp/options/trusted_types.rs`)

`TrustedTypesPolicy` 구조체는 다음과 같이 구현되어 있습니다:

- **정책 이름 검증**: 첫 문자는 알파벳, 나머지는 알파벳/숫자/`-`/`_`/`:`/`.`만 허용
- **`'allow-duplicates'` 지원**: `TrustedTypesToken::AllowDuplicates`로 구현
- **중복 제거**: `render_tokens()` 함수가 `HashSet`을 사용하여 중복 토큰 제거

**문제점**: 없음. 표준을 올바르게 구현했습니다.

#### 5.1.4. CSP 경고 시스템 (`src/csp/options/config/warnings.rs`)

CSP 설정의 잠재적 문제를 경고하는 시스템이 구현되어 있습니다:

- **경고 유형**:
  - `MissingWorkerSrcFallback`: `worker-src`, `script-src`, `default-src` 모두 없음
  - `WeakWorkerSrcFallback`: `default-src`만 있고 너무 관대함
  - `UpgradeInsecureRequestsWithoutBlockAllMixedContent`: 한쪽만 설정됨
  - `BlockAllMixedContentWithoutUpgradeInsecureRequests`: 한쪽만 설정됨
  - `RiskySchemes`: `data:`, `blob:`, `filesystem:` 스킴 사용

- **심각도 레벨**: `Info`, `Warning`, `Critical`

이는 매우 유용한 기능으로, 사용자가 안전하지 않은 CSP 설정을 사용할 때 경고를 제공합니다.

#### 5.1.5. CSP 검증 로직 (`src/csp/options/validation/validate.rs`)

CSP 옵션의 검증 로직을 확인한 결과:

- **기본 검증**: 지시어 이름과 값의 유효성 검증
- **Strict Dynamic 검증**: `'strict-dynamic'` 사용 시 host 소스와 충돌 검증
- **Worker Fallback 검증**: `worker-src` 부재 시 대체 지시어 확인
- **위험 스킴 경고**: `data:`, `blob:`, `filesystem:` 사용 시 경고

**문제점**: 검증 로직 자체는 잘 구현되어 있으나, `child-src` 지시어가 전체 enum에서 빠져있어 해당 지시어 사용 불가.

#### 5.1.6. CSP 고급 검증 (`src/csp/options/config/core.rs`)

`emit_risky_scheme_warnings()` 메서드를 검토한 결과, 매우 세밀한 위험도 평가를 수행합니다:

- **`data:` 스킴**:
  - `script-src`, `object-src`, `navigate-to` 등에서 사용 시 **Critical**
  - `img-src`, `media-src`, `font-src` 등에서 사용 시 **Warning**
- **`blob:` 스킴**:
  - `script-src`, `connect-src`에서 사용 시 **Warning**
  - 기타 지시어에서는 **Info**
- **`filesystem:` 스킴**:
  - 모든 경우 **Critical**

이는 보안 Best Practice를 잘 반영한 구현입니다.

### 5.2. Clear-Site-Data 구현 검토

`src/clear_site_data/options.rs`를 검토한 결과:

- **4가지 섹션 지원**: `cache`, `cookies`, `storage`, `executionContexts`
- **검증**: 최소 하나의 섹션이 선택되어야 함
- **직렬화**: 쉼표로 구분된 문자열 생성 (`"cache", "cookies"` 형식)

**문제점**: 없음. 표준에 부합하는 올바른 구현입니다.

### 5.3. X-Frame-Options 구현 검토

`src/x_frame_options/options.rs`를 검토한 결과:

- **2가지 정책 지원**: `DENY`, `SAMEORIGIN`
- **기본값**: `DENY`

**문제점**: deprecated된 `ALLOW-FROM` 지시어는 지원하지 않는데, 이는 올바른 선택입니다(CSP `frame-ancestors` 사용 권장). 하지만 이에 대한 문서화가 없습니다.

### 5.4. X-Content-Type-Options 구현 검토

`src/x_content_type_options/executor.rs`를 검토한 결과:

- **고정값**: 항상 `nosniff`를 설정 (유일한 유효값)
- **옵션 없음**: `NoopOptions` 사용

**문제점**: 없음. 이 헤더는 옵션이 필요 없는 단순 헤더입니다.

### 5.5. X-DNS-Prefetch-Control 구현 검토

`src/x_dns_prefetch_control/options.rs`를 검토한 결과:

- **2가지 정책**: `on`, `off`
- **기본값**: `off` (보안 강화)

**문제점**: 없음. 간단한 헤더를 올바르게 구현했습니다.

### 5.6. X-Powered-By 제거 기능

`src/x_powered_by/executor.rs`를 검토한 결과:

- **기능**: `X-Powered-By` 헤더를 삭제
- **옵션 없음**: 항상 헤더를 제거

이는 정보 노출을 방지하는 좋은 기능입니다. 많은 웹 서버/프레임워크가 기본적으로 이 헤더를 추가하므로, 이를 제거하는 기능은 유용합니다.

### 5.7. Referrer-Policy 단순 구현

`src/referrer_policy/options.rs`와 `executor.rs`를 검토한 결과:

- **8가지 정책 지원**: 모든 표준 정책 값 포함
- **기본값**: `strict-origin-when-cross-origin` (권장값)
- **단일 정책만 지원**: 이미 보고서에 언급된 문제점

### 5.8. SafeHeaders의 실제 동작

`src/safe_headers/executor.rs`는 `NormalizedHeaders::sanitize_for_http()`를 호출합니다. 이 메서드의 실제 동작을 확인하기 위해 `normalized_headers.rs`를 더 자세히 살펴봐야 하지만, 일반적으로 다음을 수행할 것으로 예상됩니다:

- HTTP 제어 문자(`\r`, `\n`) 제거
- 유효하지 않은 헤더 이름/값 제거
- Response Splitting 공격 방지

이는 기본적으로 활성화되어야 하는 중요한 보안 기능이지만, 기능 이름과 문서화 부족으로 인해 사용자가 이해하기 어렵습니다.

### 5.9. Constants 모듈 검토

`src/constants.rs`를 검토한 결과:

- **헤더 키**: 모든 보안 헤더 이름을 상수로 정의
- **헤더 값**: 각 기능의 표준 값들을 상수로 정의
- **실행 순서**: `executor_order` 모듈에서 각 기능의 실행 순서를 정의

**발견 사항**:
- `SafeHeaders`가 `order = 0`으로 가장 먼저 실행됨 (올바른 선택)
- `FetchMetadata`가 `order = 1`로 두 번째 실행 (요청 헤더 검증이 구현되면 올바른 위치)
- `Clear-Site-Data`가 `order = 16`으로 가장 마지막 실행 (올바른 선택)

이는 잘 설계된 실행 순서입니다.

### 5.10. Executor 매크로의 중복

`src/executor.rs`에는 두 가지 매크로가 있습니다:

1. **`impl_cached_header_executor!`**: 고정된 헤더 키 사용
2. **`impl_dynamic_header_executor!`**: 옵션에 따라 동적으로 헤더 키 선택 (Report-Only 모드용)

두 번째 매크로는 `fallback` 변형도 제공하여 레거시 헤더(예: `Feature-Policy`)를 함께 보낼 수 있습니다.

**문제점**: 이 매크로들은 보일러플레이트를 줄이는 데 유용하지만, 코드 추적과 디버깅을 어렵게 만듭니다. 특히 IDE의 "Go to Definition" 기능이 작동하지 않습니다.

### 5.11. Shield 구조체의 파이프라인 순서 관리

`Shield` 구조체는 `Vec<PipelineEntry>`를 사용하여 각 기능을 저장하고, `order` 필드로 정렬합니다. 이는 다음과 같은 특징이 있습니다:

**장점**:
- 실행 순서를 명확하게 제어 가능
- 동적으로 기능 추가/제거 가능

**단점**:
- 매번 `sort_by`를 호출하여 재정렬 (비효율적)
- `BinaryHeap`이나 삽입 정렬을 사용하면 더 효율적

### 5.12. PolicyMode 열거형의 제한적 사용

`PolicyMode` 열거형(`Enforce`, `ReportOnly`)이 정의되어 있지만, 테스트 빌드 외에는 `#[allow(dead_code)]` 속성이 적용되어 있습니다. 이는 다음을 의미합니다:

- Report-Only 모드가 구현되어 있지만 제한적으로만 사용됨
- `features.md`에 따르면 CSP, COEP, COOP, Permissions-Policy만 Report-Only 지원
- 다른 헤더들은 Report-Only 개념이 없음 (표준에 부합)

## 6. 기타 개선 및 보완 사항

### 6.1. 테스트 커버리지 확인 불가

각 모듈마다 `*_test.rs` 파일이 존재하여 단위 테스트가 작성되어 있는 것으로 보입니다. `tests/` 디렉토리에도 통합 테스트 파일들이 있으며, proptest를 사용한 속성 기반 테스트도 있는 것으로 보입니다(`.proptest-regressions` 파일들). 하지만 테스트 코드를 직접 검토하지 않아 테스트 커버리지나 테스트의 품질을 판단할 수 없습니다. 보안 라이브러리의 특성상 엣지 케이스와 공격 시나리오에 대한 철저한 테스트가 필수적이므로, 테스트 코드에 대한 별도의 검토가 필요합니다.

### 6.2. 에러 처리의 일관성 부족

대부분의 `Options` 구조체는 `FeatureOptions` 트레이트를 구현하며, `validate()` 메서드를 통해 유효성을 검증합니다. 하지만 일부 옵션(예: `CoepOptions`, `CoopOptions`, `CorpOptions`)은 `validate()` 메서드에서 항상 `Ok(())`를 반환하며, `Error` 타입으로 `std::convert::Infallible`을 사용합니다.

이는 현재 해당 옵션에 검증할 내용이 없다는 의미이지만, 다음과 같은 문제를 야기할 수 있습니다.

- **일관성 부족**: 일부 옵션은 복잡한 검증을 수행하고, 일부는 아무것도 하지 않아 일관성이 떨어집니다.
- **미래 확장성**: 나중에 검증 로직을 추가하려면 `Error` 타입을 변경해야 하는데, 이는 breaking change입니다.

모든 옵션이 동일한 검증 인터페이스를 가지는 것은 좋지만, 실제로 검증이 필요 없는 경우 트레이트 구현 자체를 선택적으로 만드는 것도 고려할 수 있습니다.

**추가 발견**: `grep_search` 결과, 총 23개의 에러 타입이 정의되어 있습니다. 이는 각 모듈이 독립적인 에러 타입을 가지고 있다는 것을 의미합니다. 이는 세밀한 에러 처리를 가능하게 하지만, 사용자가 모든 에러 타입을 개별적으로 처리해야 하는 부담을 줍니다. 공통 에러 타입을 도입하거나, 각 에러를 `ShieldError`로 통합하는 것을 고려할 수 있습니다.

### 6.3. 문서화(Documentation) 부재

코드 전반에 걸쳐 Rust의 공식 문서화 주석(`///`, `//!`)이 거의 보이지 않습니다. 오픈소스 라이브러리, 특히 보안 관련 라이브러리는 다음과 같은 문서화가 필수적입니다.

- **모듈 수준 문서**: 각 모듈이 어떤 보안 헤더를 다루는지, 왜 필요한지에 대한 설명
- **공개 API 문서**: 각 구조체, 열거형, 함수의 역할과 사용 예제
- **보안 고려사항**: 각 기능이 방어하는 공격 유형과 올바른 사용법

`cargo doc`으로 생성되는 문서가 거의 비어있을 것으로 예상되며, 이는 라이브러리의 채택률과 신뢰성에 부정적인 영향을 미칩니다.

**검증 결과**: 실제로 코드 전반에 걸쳐 `///` 주석이 거의 없습니다. 공개 API(`pub struct`, `pub enum`, `pub fn`)에 대한 문서화가 전무하며, 모듈 수준 문서(`//!`)도 찾을 수 없습니다. 이는 오픈소스 라이브러리로서 치명적인 약점입니다.

### 6.4. 예제 및 통합 가이드 부족

`README.md`나 `examples/` 디렉토리를 검토하지 못했지만, 라이브러리의 실용성을 높이기 위해서는 다음이 필요합니다.

- **실전 예제**: 실제 웹 프레임워크(예: Axum, Actix-web, Rocket)와의 통합 예제
- **보안 정책 템플릿**: 일반적인 사용 사례(SPA, API 서버, 정적 사이트 등)별 권장 보안 헤더 설정
- **마이그레이션 가이드**: 다른 라이브러리에서 이 라이브러리로 전환하는 방법

**검증 결과**: 워크스페이스 구조에 `examples/` 디렉토리가 없습니다. `benches/bunner_shield_rs.rs` 벤치마크 파일은 존재하지만, 이는 성능 측정용이지 사용 예제가 아닙니다.

### 6.5. 의존성 최소화 검토

`Cargo.toml`을 보면 다음과 같은 의존성을 사용하고 있습니다:
- `thiserror`: 에러 타입 정의용
- `hmac`, `sha2`: CSRF 토큰 HMAC 생성용
- `url`: URL 파싱용
- `zeroize`: 민감한 데이터(CSRF 비밀키) 제로화용
- `rand`: 난수 생성용
- `base64`: Base64 인코딩용

이 중 `hmac`, `sha2`, `rand`, `base64`는 CSRF 기능만을 위한 것입니다. CSRF 기능에 치명적인 결함(토큰 검증 로직 부재)이 있는 상태에서 이러한 의존성을 유지하는 것은 비효율적입니다. CSRF 기능을 올바르게 완성하거나, 또는 해당 기능을 별도의 feature flag로 분리하여 선택적으로 포함할 수 있도록 하는 것이 좋습니다.

**추가 발견**: `url` 크레이트는 CSRF의 Origin 검증에만 사용됩니다. Origin 검증도 현재 Host 헤더 기반으로 구현되어 있어 보안 문제가 있으므로, 의존성 최적화와 함께 기능 개선이 필요합니다.

### 6.6. CSP 모듈의 복잡한 구조

`bunner-shield-rs` 라이브러리는 현대적인 웹 보안 헤더를 지원하려는 좋은 목표를 가지고 있으나, **오픈소스 웹서버 코어 보안 라이브러리로 실전 배포하기에는 다음과 같은 치명적인 결함과 부족함이 있습니다**:

### 치명적인 문제 (즉시 해결 필요)

1. **CSRF 토큰 검증 로직 누락**: 토큰 발급 기능만 있고, 실제 요청에서 토큰을 검증하는 로직이 `Csrf` executor에 전혀 없어 CSRF 방어 기능이 작동하지 않음
2. **Fetch Metadata 요청 검증 로직 누락**: `Vary` 헤더만 추가하고 실제 `Sec-Fetch-*` 헤더를 검증하는 핵심 보안 로직이 없음
3. **Cargo.toml의 유효하지 않은 Rust 에디션**: 빌드 불가능한 `edition = "2024"` 설정

### 주요 개선 사항 (표준 준수 및 기능 완성)

4. **CSP `child-src` 지시어 누락**: `frame-src`와 `worker-src`의 fallback 지시어 미지원
5. **CSP `report-uri` 지시어 누락**: 구형 브라우저 호환성을 위한 deprecated 지시어 미지원
6. **Referrer-Policy fallback 미지원**: 쉼표로 구분된 다중 정책 설정 불가
7. **Permissions-Policy allowlist 직렬화 오류**: Origin에 큰따옴표가 자동으로 추가되지 않음
8. **CSRF Origin 검증의 Host 헤더 기반 취약점**: 동적으로 생성된 허용 목록이 위조 가능
9. **Set-Cookie 다중 헤더 처리 오류**: `NormalizedHeaders::into_result()`가 여러 `Set-Cookie`를 하나로 병합하여 HTTP 명세 위반
10. **HSTS `preload` 기본 `max-age` 미준수**: 1년 대신 2년(권장값) 설정 필요

### 설계 및 DX 개선사항

11. **과도한 추상화**: `FeatureExecutor`, `DynFeatureExecutor`, `CachedHeader` 등 불필요한 간접 레이어
12. **빌더 패턴의 비효율적인 오류 처리**: `Result<Self, Error>` 반환으로 체이닝 불편
13. **일관성 없는 모듈 구조**: `csp`, `csrf`는 하위 디렉토리 구조, 나머지는 단순 파일 구조
14. **과도한 `pub use`**: 내부 오류 타입 등 불필요한 API 노출
15. **SafeHeaders 기능의 모호성**: 기능 이름과 역할이 불명확하고 문서화 부재
16. **문서화 전무**: `///` 주석이 거의 없어 `cargo doc` 생성 문서가 거의 비어있음
17. **예제 및 통합 가이드 부족**: 실제 웹 프레임워크와의 통합 예제 부재
18. **에러 처리 일관성 부족**: 일부는 `Infallible`, 일부는 복잡한 에러 타입 사용

### 보안 기능 추가 요구사항

19. **CSRF 요청 검증 미들웨어 필요**: 현재 응답 헤더만 설정하는 구조로는 요청 검증 불가능
20. **Fetch Metadata 검증 엔진 필요**: 사용자 정의 규칙에 따른 `Sec-Fetch-*` 헤더 검증 로직
21. **CsrfReplayStore 구현체 제공**: 토큰 재사용 방지를 위한 저장소 인터페이스만 있고 구현체 없음
22. **CSRF 토큰 자동 만료**: `verify` 메서드가 타임스탬프를 무시하여 영구 유효 토큰 발생

### 부가적 개선사항

23. **의존성 최적화**: CSRF 전용 의존성(`hmac`, `sha2`, `rand`, `base64`)을 feature flag로 분리
24. **테스트 커버리지**: 단위 테스트 파일은 존재하나 커버리지와 엣지 케이스 테스트 확인 불가
25. **CSP `block-all-mixed-content` deprecated 표시**: 사용자에게 `upgrade-insecure-requests` 권장 안내 필요

### 결론

이 라이브러리는 **현재 상태로는 프로덕션 환경에 배포할 수 없습니다**. 특히:

- **CSRF 기능**은 검증 로직이 없어 완전히 무용지물입니다
- **Fetch Metadata 기능**은 이름만 있고 실제 보안 기능이 없습니다
- **빌드 설정**이 잘못되어 컴파일조차 불가능할 수 있습니다

최우선적으로 위의 **치명적인 문제 3가지**를 해결한 후, **주요 개선 사항 10가지**를 순차적으로 처리하고, 마지막으로 **설계 및 DX 개선사항**을 적용해야 실용적이고 신뢰할 수 있는 보안 라이브러리가 될 수 있습니다.

---

## 추가 정정 및 최신 구현 반영 (2025-10-31)

아래 항목들은 코드 전체 재검토 결과, 기존 서술을 보완/정정하거나 새롭게 확인된 부족사항입니다. 기존 본문은 유지하고, 여기에 추가로 기록합니다.

### A. Fetch Metadata 구현 상태 정정 및 보완 요구

- 정정: `src/fetch_metadata/executor.rs`를 재검토한 결과, 이 모듈은 단순히 `Vary` 헤더를 추가하는 수준이 아니라 실제로 수신된 요청의 `Sec-Fetch-*` 헤더를 파싱/검증하여 차단까지 수행합니다.
  - `Sec-Fetch-Site`가 `cross-site`일 때, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`를 조합하여 허용 여부를 결정하고, 위반 시 `FetchMetadataError::CrossSiteBlocked`로 실패를 반환합니다.
  - `allow_legacy_clients`가 비활성화된 경우, 필수 헤더가 없으면 `MissingHeaders` 또는 `HeaderMissing` 에러를 반환합니다.
- 여전히 남는 문제:
  - 이 라이브러리의 실행 모델상, 해당 검증 실패는 응답 헤더 단계(파이프라인)에서 에러로 propagate 됩니다. 실제 웹서버(요청 핸들러) 관점에서 “요청 거부(예: 403)”로 매핑하는 통합 지점/가이드가 없습니다. 즉, 보안 정책 위반을 HTTP 응답 코드로 일관되게 변환하는 어댑터 계층이 부재합니다.
  - 문서화 부족: 어떤 `FetchMetadataOptions` 조합이 어떤 요청을 허용/차단하는지, 프레임워크(Axum/Actix 등)에서 어떻게 연결하는지 안내가 없습니다.
  - 권장 추가: 정책 위반 시 반환할 표준화된 결정(예: 403, 텍스트 바디, 로깅/계측)을 선택적으로 내보내는 Strategy/Hook를 옵션으로 제공하십시오.

결론: “핵심 로직 부재” 평가는 정정합니다. 다만, “서버 통합 설계/문서화의 부재”는 여전히 실전 가치를 떨어뜨리는 중대한 DX 결함으로 남아 있습니다.

### B. CSRF 실행기 동작 재확인

- `src/csrf/executor.rs`는 토큰 발급 외에 선택적으로 Origin/Referer 검증을 수행하지만, 여전히 “요청 본문/헤더의 CSRF 토큰 검증”은 수행하지 않습니다. 즉, 실제 상태 변이 요청(POST/PUT/DELETE 등)에 대해 `X-CSRF-Token`을 확인하여 거부하는 흐름이 없습니다.
- 또한 Origin 검증은 요청의 `Host` 헤더를 신뢰하여 허용 출처를 유추하는데, `Host`는 위조 가능하므로 안전하지 않습니다. 정적 허용 목록 기반으로 전환해야 합니다.

### C. Permissions-Policy Report-Only와 브라우저 호환성

- 라이브러리는 `Permissions-Policy-Report-Only` 헤더를 사용합니다(`constants::header_keys`). 이 헤더는 Chromium 계열에서만 부분적으로 지원되는 신생/실험적 성격이 강하며, Safari/Firefox 호환성이 제한적입니다.
- 코드상 Report-Only 모드에서는 레거시 `Feature-Policy` 헤더를 함께 내보내는 폴백이 구현되어 있습니다. 그러나 `Feature-Policy`에는 Report-Only 개념이 표준화되어 있지 않았습니다. 동일 값을 그대로 보내는 전략은 브라우저별로 의미가 다를 수 있습니다.
- 권장: 공식 호환성 표(Chromium Platform Status/MDN) 요약을 문서에 포함하고, Report-Only를 사용할 때의 기대 동작과 한계를 명확히 고지하십시오.

### D. Permissions-Policy 빌더 직렬화 문제 구체화

- `src/permissions_policy/options.rs`의 `PolicyBuilder`는 `AllowListItem::Origin`을 문자열 그대로 사용합니다. 명세상 출처는 큰따옴표로 감싸는 것이 요구되는 맥락이 많습니다. 현재 구현은 자동 인용을 하지 않아 사용자가 직접 따옴표를 넣지 않으면 비표준 형식이 생성될 수 있습니다.
- 권장: 빌더 내부에서 `"https://origin"`으로 자동 보정하거나, 최소한 문서/경고를 제공합니다.

### E. NormalizedHeaders의 Set-Cookie 병합 동작 확인

- `src/normalized_headers.rs`에서 `Set-Cookie`는 `multi_value=true`로 관리하지만, `into_result()`는 최종적으로 각 헤더의 값을 `\n`으로 이어붙인 단일 문자열로 반환합니다. 이는 HTTP 명세(RFC 6265/7230)의 “Set-Cookie는 병합 금지” 원칙과 상충합니다.
- 권장: 반환 타입을 변경할 수 없다면(BC 고려), 최소한 `Shield::secure()`의 결과를 실제 서버에 적용하는 계층에서 `Set-Cookie`를 개별 헤더로 분기해 내보내도록 가이드하십시오. 장기적으로는 API를 `HashMap<String, Vec<String>>` 형태로 확장하는 것이 바람직합니다.

### F. API 표면 과다 공개 확인

- `src/lib.rs`는 내부 오류 타입/세부 구현(`CspNonceManagerError`, `FetchMetadataParseError` 등)까지 광범위하게 `pub use`로 노출합니다. 이는 외부 사용자에게 불필요한 결합을 강요하고, API 안정성에 불리합니다.
- 권장: 필수 타입만 노출하고, 세부 오류는 모듈 경로로 접근하게 하여 표면을 축소하십시오.

### G. 패키징/문서화 결함 추가 발견

- `Cargo.toml`은 `readme = "README.md"`를 가리키지만, 저장소 루트에 `README.md`가 없습니다. 이는 패키징 시 오류를 유발합니다.
- `docs/` 디렉터리는 존재하나 비어 있습니다. 문서화가 사실상 전무합니다.
- 기존 지적한 `edition = "2024"` 문제와 함께, 기본 메타(README) 부재는 배포/사용 신뢰도를 크게 떨어뜨립니다.

### H. 브라우저/표준 세부 항목 최신화 제안

- CSP 지시어 집합에서 `child-src`는 여전히 누락되어 있습니다(검증: `src/csp/options/types.rs`).
- `report-uri`는 deprecated지만 구형 브라우저 호환성 측면에서 선택적 지원을 고려할 가치가 있습니다.
- `Permissions-Policy-Report-Only`의 호환성 범위를 문서로 명시해, 사용자 혼란을 줄이십시오.

### I. 운영 및 관측성(Observability) 부족

- Report-Only 위반이나 정책 차단 이벤트를 로깅/계측에 통합하는 코드/가이드가 없습니다. 최소한 Trait Hook(예: `on_violation`)이나 `log`/`tracing` 연동 옵션을 제공하십시오.

### J. 기능 플래그 및 슬림 빌드 제안

- CSRF 관련 의존성(`hmac`, `sha2`, `rand`, `base64`)은 상대적으로 무겁습니다. 해당 기능을 feature flag로 분리해 슬림 빌드를 가능하게 하면 코어 웹서버에 유리합니다.

### K. 실행 파이프라인과 요청 처리의 경계 명확화

- 현재 파이프라인은 “헤더 가공/검증”을 응답 생성 타이밍에 수행한다고 가정하고 있습니다. 하지만 Fetch Metadata/CSRF처럼 “요청 거부”가 필요한 기능은 **요청 단계**에서의 판단과 **응답 단계**에서의 헤더 설정이 명확히 분리되어야 합니다.
- 권장: 요청 전용 검증 인터페이스(예: `RequestInspector`)를 도입하고, 서버 프레임워크별 어댑터(Axum extractor/Actix middleware)를 별도 크레이트로 제공하십시오.

### L. 전체 모듈 커버리지 체크리스트 (완료)

다음 각 모듈과 파일을 재검토하여 표준 준수/기능 완성/설계 일관성 여부를 확인했습니다.

- Core
  - `src/lib.rs` — API 표면 과다 공개 지적, 모듈 export 확인
  - `src/shield.rs` — 파이프라인/순서/Result 체인 DX 지적
  - `src/executor.rs` — 매크로/추상화, Report-Only 동적 키 확인
  - `src/constants.rs` — 키/값/순서 상수 검토
  - `src/normalized_headers.rs` — Set-Cookie 병합 문제 확인, sanitize 동작 확인
- CSP
  - `src/csp/options/{types,sources,sandbox,trusted_types}.rs` — 지시어 집합/표현/검증
  - `src/csp/options/config/{core,errors,warnings,builder_api}.rs` — 경고 및 렌더링
  - `src/csp/options/validation/{validate,strict_dynamic,source_expression,directive_value}.rs`
  - 누락: `child-src` (의도/누락 여부 확인됨)
- CSRF
  - `src/csrf/{executor,options,origin,token}.rs` — 발급/검증 메서드 존재, executor 검증 부재
- Fetch Metadata
  - `src/fetch_metadata/{executor,options}.rs` — 실제 파싱/검증/차단 구현 확인, 통합 가이드 부재
- COEP/COOP/CORP
  - `src/coep/{options,executor}.rs` — Report-Only 지원, header key 전환 로직 확인
  - `src/coop/{options,executor}.rs` — 동일 패턴
  - `src/corp/{options,executor}.rs` — CORP는 Report-Only 미해당, 올바름
- HSTS
  - `src/hsts/{options,executor}.rs` — preload 조건과 최소 max-age(31,536,000) 검증 확인
- Referrer-Policy
  - `src/referrer_policy/{options,executor}.rs` — 단일 정책만; fallback 미지원 지적
- Permissions-Policy
  - `src/permissions_policy/{options,executor}.rs` — Report-Only/Feature-Policy fallback, 빌더 인용 문제
- SameSite
  - `src/same_site/{options,executor}.rs` — 속성 강제 로직 정상, 세부 제어 부재 지적
- X-* and SafeHeaders
  - `x_content_type_options`, `x_frame_options`, `x_dns_prefetch_control`, `x_powered_by`, `safe_headers` — 구현 확인, 명세 준수/모호성 지적
- Origin-Agent-Cluster
  - `src/origin_agent_cluster/{options,executor}.rs` — 기본 enable `?1`, disable 지원 확인
- Clear-Site-Data
  - `src/clear_site_data/options.rs` — 최소 1개 섹션 요구 검증, 직렬화 확인
- 패키징/문서/메타
  - `Cargo.toml` — edition 문제, README 부재
  - `LICENSE.md` — MIT 명시 확인
  - `Makefile` — lint/format/test/bench/doc/audit/coverage/publish 타깃 확인(유용), README/doc 컨텐츠는 여전히 없음
  - `docs/` — 빈 디렉터리
  - `features.md` — Report-Only 인프라 완료 체크 확인
  - `benches/` — 존재 확인
  - `tests/` — 각 기능별 통합 테스트 파일 존재 및 proptest 회귀 데이터 존재 확인(품질 평가는 별도 과업)

요약: 모듈 전 범위를 다시 점검했으며, 본 문서의 모든 지적 사항은 해당 소스 확인을 바탕으로 합니다.

### M. HSTS `preload` 기본값 재검토

- `src/hsts/options.rs`의 `PRELOAD_MIN_MAX_AGE` 값은 `31_536_000`(1년)으로 설정되어 있으며, `preload` 활성화 시 `max-age`가 이 이상인지 검증합니다. 최신 `hstspreload.org` 사양 역시 최소 1년(31536000초)을 요구하므로, 본 라이브러리의 기본값은 국제 표준과 브라우저 요구 사항을 충족합니다.
- 본문 2.1.1에서 2년을 권장 기본값으로 제시한 부분은 사실과 다르므로, 현 구현이 기본 요구사항을 충족한다는 점을 명확히 합니다. 단, 조직 정책상 2년 이상을 강제하고 싶다면 옵션에서 `max_age`를 상향할 수 있도록 문서 안내가 필요합니다.

### N. `Set-Cookie` 직렬화의 HTTP 명세 위반 및 헤더 주입 위험

- `src/normalized_headers.rs`의 `HeaderEntry::update_joined`는 다중 값 헤더(`Set-Cookie`)를 처리할 때 값을 `"\n"` 문자로 연결합니다. 이후 `sanitize_for_http()`가 값 내 제어 문자를 공백으로 치환하지만, `join("\n")`에서 다시 줄바꿈이 삽입되어 최종 `HashMap`에 개행 문자가 그대로 남습니다.
- HTTP/1.1(RFC 7230)과 RFC 6265에 따르면 `Set-Cookie`는 헤더 병합이 금지되며, 개별 헤더 라인으로 전송되어야 합니다. 현재 구현은 하나의 값에 줄바꿈을 포함시켜 사실상 다중 헤더를 흉내내므로 명세 위반이며, 서버/프레임워크에 따라 헤더 인젝션·응답 스플리팅 취약점으로 이어질 수 있습니다.
- 통합 테스트(`tests/integration.rs`) 역시 개행으로 분리된 단일 문자열을 기대하고 있어 문제를 고착화합니다. `NormalizedHeaders::into_result()`가 `Vec<String>` 또는 `(String, Vec<String>)` 형태를 반환하도록 API를 재설계하고, 각 프레임워크 어댑터에서 실제 다중 헤더로 확장하도록 개선이 필요합니다.

### O. 요청/응답 컨텍스트 혼합으로 인한 헤더 반사 및 통합 곤란

- `Shield::secure`는 단일 `HashMap<String, String>`을 받아 모든 실행기를 적용합니다. `FetchMetadata` 처럼 요청 헤더 검증을 수행하는 기능과 `Csp`·`Hsts`처럼 응답 헤더를 추가하는 기능을 동시에 구성하면, 요청에서 받은 민감한 헤더(`Origin`, `Sec-Fetch-*`, 등)가 정규화된 채 최종 결과 맵에 그대로 남아 응답에 재전송될 위험이 있습니다.
- 실제로 `FetchMetadata`와 `Csrf` 테스트는 요청 헤더만 전달하고 결과 맵이 동일하다고 가정합니다(`tests/fetch_metadata.rs`). 반면 다수의 통합 테스트는 응답 헤더를 조작하기 위한 시나리오입니다. 즉, 동일 API가 상반되는 컨텍스트에서 사용되고 있어 사용자가 오용하기 쉬우며, 헤더 반사·정보 누출·캐시 오염 가능성을 내포합니다.
- 명확한 분리 없이 단일 파이프라인에 모든 기능을 삽입하도록 유도하는 현재 설계는 DX를 떨어뜨릴 뿐 아니라 보안 통제도 약화시킵니다. 요청 전용 인터페이스와 응답 전용 인터페이스를 분리하고, 공용 헬퍼로만 공유 로직을 노출하도록 재설계해야 합니다. 최소한 문서에서 `Shield::secure`가 반환한 맵을 그대로 응답으로 사용하지 말고, 응답용 헤더만 추출하는 절차를 권장해야 합니다.

