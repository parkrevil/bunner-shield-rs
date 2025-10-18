# Feature Options 목록

이 문서는 bunner-shield-rs crate가 제공하는 모든 Feature의 공개 옵션 API를 Feature별로 정리한 자료입니다. 각 항목에는 주요 타입과 메서드 시그니처를 빠짐없이 나열했으며, 기준일은 2025-10-19입니다.

## Content Security Policy (CSP)

### CspOptions (`src/csp/options.rs`)

#### 생성 및 유틸리티
- `new() -> Self` 기본값(빈 directive 집합)으로 시작하는 옵션 빌더를 생성합니다.
- `header_value(&self) -> String` 누적된 directive를 CSP 헤더 문자열로 직렬화합니다.
- `validate_with_warnings(&self) -> Result<Vec<CspOptionsWarning>, CspOptionsError>` 정합성을 검사하고 경고 목록을 반환합니다.
- `merge(self, other: &CspOptions) -> Self` 다른 옵션에서 directive를 병합합니다.
- `add_source(self, directive: CspDirective, source: impl Into<CspSource>) -> Self` 특정 directive에 source 토큰을 추가합니다.

#### 기본 Directive 지정
아래 source setter는 공통으로 `I: IntoIterator<Item = S>` 및 `S: Into<CspSource>` 제약을 사용합니다.
- `default_src<I, S>(self, sources: I) -> Self` `default-src` directive를 설정합니다.
- `script_src<F>(self, configure: F) -> Self` `F: FnOnce(ScriptSrcBuilder<'_>) -> ScriptSrcBuilder<'_>` 클로저를 통해 `script-src`, `script-src-elem`, `script-src-attr` directive를 구성합니다.
- `style_src<F>(self, configure: F) -> Self` `F: FnOnce(StyleSrcBuilder<'_>) -> StyleSrcBuilder<'_>` 클로저를 통해 `style-src`, `style-src-elem`, `style-src-attr` directive를 구성합니다.
- `img_src<I, S>(self, sources: I) -> Self` `img-src` directive를 설정합니다.
- `connect_src<I, S>(self, sources: I) -> Self` `connect-src` directive를 설정합니다.
- `font_src<I, S>(self, sources: I) -> Self` `font-src` directive를 설정합니다.
- `frame_src<I, S>(self, sources: I) -> Self` `frame-src` directive를 설정합니다.
- `worker_src<I, S>(self, sources: I) -> Self` `worker-src` directive를 설정합니다.

#### 기타 리소스 Directive
- `navigate_to<I, S>(self, sources: I) -> Self` `navigate-to` directive를 설정합니다.
- `object_src<I, S>(self, sources: I) -> Self` `object-src` directive를 설정합니다.
- `media_src<I, S>(self, sources: I) -> Self` `media-src` directive를 설정합니다.
- `manifest_src<I, S>(self, sources: I) -> Self` `manifest-src` directive를 설정합니다.
- `frame_ancestors<I, S>(self, sources: I) -> Self` `frame-ancestors` directive를 설정합니다.
- `base_uri<I, S>(self, sources: I) -> Self` `base-uri` directive를 설정합니다.
- `form_action<I, S>(self, sources: I) -> Self` `form-action` directive를 설정합니다.

#### Trusted Types 설정
- `trusted_types_tokens<I>(self, tokens: I) -> Self` Trusted Types 토큰 목록을 설정합니다.
- `trusted_types_policies<I>(self, policies: I) -> Self` 정책 컬렉션을 Trusted Types 토큰으로 변환해 설정합니다.
- `trusted_types_none(self) -> Self` `trusted-types 'none'` directive를 지정합니다.

#### 보안 플래그 및 리포트
- `require_trusted_types_for_scripts(self) -> Self` `require-trusted-types-for 'script'` directive를 추가합니다.
- `upgrade_insecure_requests(self) -> Self` `upgrade-insecure-requests` 플래그를 활성화합니다.
- `block_all_mixed_content(self) -> Self` `block-all-mixed-content` 플래그를 활성화합니다.
- `sandbox(self) -> Self` 인자 없는 `sandbox` directive를 설정합니다.
- `sandbox_with<I>(self, tokens: I) -> Self` `sandbox` directive에 허용 토큰을 부여합니다.
- `report_to(self, group: impl Into<String>) -> Self` `report-to` directive를 특정 그룹으로 지정합니다.

#### Nonce 생성 도우미
- `generate_nonce() -> String` 기본 길이(32바이트)의 base64 nonce를 생성합니다.
- `generate_nonce_with_size(byte_len: usize) -> String` 원하는 길이의 base64 nonce를 생성합니다.

#### ScriptSrcBuilder (`src/csp/options.rs`)
`script_src` 클로저는 `ScriptSrcBuilder<'_>` 인스턴스를 받아 체이닝 방식으로 directive를 구성합니다.
- `sources<I, S>(self, sources: I) -> Self` `script-src` directive에 source 토큰을 설정합니다.
- `elem<I, S>(self, sources: I) -> Self` `script-src-elem` directive를 구성합니다.
- `attr<I, S>(self, sources: I) -> Self` `script-src-attr` directive를 구성합니다.
- `nonce(self, nonce: impl Into<String>) -> Self` 문자열 nonce를 Sanitization 후 `script-src`에 추가합니다.
- `nonce_value(self, nonce: CspNonce) -> Self` `CspNonce` 값을 사용해 nonce 토큰을 추가합니다.
- `hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` 지정 알고리즘 hash 토큰을 `script-src`에 추가합니다.
- `elem_nonce(self, nonce: impl Into<String>) -> Self` `script-src-elem` directive에 nonce 토큰을 추가합니다.
- `elem_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` `script-src-elem` directive에 hash 토큰을 추가합니다.
- `attr_nonce(self, nonce: impl Into<String>) -> Self` `script-src-attr` directive에 nonce 토큰을 추가합니다.
- `attr_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` `script-src-attr` directive에 hash 토큰을 추가합니다.
- `strict_dynamic(self) -> Self` `'strict-dynamic'` 토큰을 `script-src`에 추가합니다.

#### StyleSrcBuilder (`src/csp/options.rs`)
`style_src` 클로저는 `StyleSrcBuilder<'_>` 인스턴스를 통해 style 관련 directive를 구성합니다.
- `sources<I, S>(self, sources: I) -> Self` `style-src` directive를 설정합니다.
- `elem<I, S>(self, sources: I) -> Self` `style-src-elem` directive를 설정합니다.
- `attr<I, S>(self, sources: I) -> Self` `style-src-attr` directive를 설정합니다.
- `nonce(self, nonce: impl Into<String>) -> Self` `style-src` directive에 nonce 토큰을 추가합니다.
- `hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` `style-src` directive에 hash 토큰을 추가합니다.
- `elem_nonce(self, nonce: impl Into<String>) -> Self` `style-src-elem` directive에 nonce 토큰을 추가합니다.
- `elem_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` `style-src-elem` directive에 hash 토큰을 추가합니다.
- `attr_nonce(self, nonce: impl Into<String>) -> Self` `style-src-attr` directive에 nonce 토큰을 추가합니다.
- `attr_hash(self, algorithm: CspHashAlgorithm, hash: impl Into<String>) -> Self` `style-src-attr` directive에 hash 토큰을 추가합니다.

### 관련 타입 (`src/csp/options.rs`)
- `CspSource` (enum): SelfKeyword, None, UnsafeInline, UnsafeEval, UnsafeHashes, WasmUnsafeEval, StrictDynamic, ReportSample, Wildcard, Scheme(Cow<'static, str>), Host(Cow<'static, str>), Nonce(String), Hash { algorithm, value }, Custom(String); 생성자 `scheme(...)`, `host(...)`, `raw(...)`를 제공합니다.
- `CspDirective` (enum): 25개 CSP directive를 표현하며 `ALL` 상수 배열과 `as_str(self) -> &'static str` 메서드를 노출합니다.
- `CspHashAlgorithm` (enum): `Sha256`, `Sha384`, `Sha512` 알고리즘 식별자를 제공합니다.
- `SandboxToken` (enum): allow-downloads, allow-forms, allow-modals 등 `sandbox` directive에서 허용 가능한 모든 토큰을 열거합니다.
- `TrustedTypesPolicy` (struct): `new(name: impl Into<String>)`, `as_str(&self)`, `into_string(self)` 메서드를 제공합니다.
- `TrustedTypesToken` (enum): `policy(TrustedTypesPolicy) -> Self`, `allow_duplicates() -> Self` 생성자를 제공합니다.
- `CspNonce` (struct): `as_str(&self)`, `header_value(&self)`, `into_inner(self)`로 nonce 값을 노출합니다.
- `CspNonceManager` (struct): `new()`, `with_size(byte_len: usize)`, `issue(&self)`, `issue_header_value(&self)`, `byte_len(&self)`를 통해 nonce 발급을 관리합니다.

## Cross-Site Request Forgery (CSRF)

### CsrfOptions (`src/csrf/options.rs`)
- `new(secret_key: [u8; 32]) -> Self` 32바이트 비밀키를 사용해 기본 옵션을 생성합니다.
- `cookie_name(self, cookie_name: impl Into<String>) -> Self` CSRF 쿠키 이름을 커스터마이즈합니다.
- `token_length(self, length: usize) -> Self` 발급할 토큰 길이를 지정합니다.

## SameSite Cookie

### SameSiteOptions (`src/same_site/options.rs`)
- `new() -> Self` 기본 설정(Secure=true, HttpOnly=true, SameSite=Lax)으로 생성합니다.
- `secure(self, secure: bool) -> Self` Secure 플래그를 지정합니다.
- `http_only(self, http_only: bool) -> Self` HttpOnly 플래그를 지정합니다.
- `same_site(self, same_site: SameSitePolicy) -> Self` SameSite 정책을 Lax/Strict/None 중 하나로 설정합니다.

### 관련 타입
- `SameSitePolicy` (enum): `Lax`, `Strict`, `None` 값을 제공합니다.

## HTTP Strict Transport Security (HSTS)

### HstsOptions (`src/hsts/options.rs`)
- `new() -> Self` 기본 max-age(31,536,000초)로 생성합니다.
- `max_age(self, seconds: u64) -> Self` `max-age` 값을 초 단위로 설정합니다.
- `include_subdomains(self) -> Self` `includeSubDomains` 플래그를 활성화합니다.
- `preload(self) -> Self` `preload` 플래그를 활성화합니다.
- `header_value(&self) -> String` 구성된 HSTS 헤더 문자열을 생성합니다.

## Clear-Site-Data

### ClearSiteDataOptions (`src/clear_site_data/options.rs`)
- `new() -> Self` 모든 섹션이 비활성화된 상태로 생성합니다.
- `cache(self) -> Self` `"cache"` 섹션을 활성화합니다.
- `cookies(self) -> Self` `"cookies"` 섹션을 활성화합니다.
- `storage(self) -> Self` `"storage"` 섹션을 활성화합니다.
- `execution_contexts(self) -> Self` `"executionContexts"` 섹션을 활성화합니다.

## Cross-Origin Embedder Policy (COEP)

### CoepOptions (`src/coep/options.rs`)
- `new() -> Self` 기본 정책(`RequireCorp`)으로 생성합니다.
- `policy(self, policy: CoepPolicy) -> Self` 정책을 수동으로 지정합니다.
- `policy_from_str(self, policy: &str) -> Result<Self, CoepOptionsError>` 문자열에서 정책을 파싱해 적용합니다.
- `from_policy_str(policy: &str) -> Result<Self, CoepOptionsError>` 문자열 정책으로 새 빌더를 생성합니다.

### 관련 타입
- `CoepPolicy` (enum): `RequireCorp`, `Credentialless` 값을 가집니다.

## Cross-Origin Opener Policy (COOP)

### CoopOptions (`src/coop/options.rs`)
- `new() -> Self` 기본 정책(`SameOrigin`)으로 생성합니다.
- `policy(self, policy: CoopPolicy) -> Self` 정책을 수동으로 지정합니다.
- `policy_from_str(self, policy: &str) -> Result<Self, CoopOptionsError>` 문자열에서 정책을 파싱해 적용합니다.
- `from_policy_str(policy: &str) -> Result<Self, CoopOptionsError>` 문자열 정책으로 새 빌더를 생성합니다.

### 관련 타입
- `CoopPolicy` (enum): `SameOrigin`, `SameOriginAllowPopups`, `UnsafeNone` 값을 가집니다.

## Cross-Origin Resource Policy (CORP)

### CorpOptions (`src/corp/options.rs`)
- `new() -> Self` 기본 정책(`SameOrigin`)으로 생성합니다.
- `policy(self, policy: CorpPolicy) -> Self` 정책을 수동으로 지정합니다.
- `policy_from_str(self, policy: &str) -> Result<Self, CorpOptionsError>` 문자열에서 정책을 파싱해 적용합니다.
- `from_policy_str(policy: &str) -> Result<Self, CorpOptionsError>` 문자열 정책으로 새 빌더를 생성합니다.

### 관련 타입
- `CorpPolicy` (enum): `SameOrigin`, `SameSite`, `CrossOrigin` 값을 가집니다.

## Permissions-Policy

### PermissionsPolicyOptions (`src/permissions_policy/options.rs`)
- `new(policy: impl Into<String>) -> Self` 전체 정책 문자열을 설정하며 생성합니다.
- `policy(self, policy: impl Into<String>) -> Self` 이미 생성된 옵션의 정책 문자열을 덮어씁니다.

## Referrer-Policy

### ReferrerPolicyOptions (`src/referrer_policy/options.rs`)
- `new() -> Self` 기본 정책(`StrictOriginWhenCrossOrigin`)으로 생성합니다.
- `policy(self, policy: ReferrerPolicyValue) -> Self` 정책을 지정합니다.

### 관련 타입
- `ReferrerPolicyValue` (enum): `NoReferrer`, `NoReferrerWhenDowngrade`, `SameOrigin`, `Origin`, `StrictOrigin`, `OriginWhenCrossOrigin`, `StrictOriginWhenCrossOrigin`, `UnsafeUrl` 값을 가집니다.

## Origin-Agent-Cluster

### OriginAgentClusterOptions (`src/origin_agent_cluster/options.rs`)
- `new() -> Self` 기본값(`?1`)으로 생성합니다.
- `enable(self) -> Self` `Origin-Agent-Cluster: ?1` 값을 명시합니다.
- `disable(self) -> Self` `Origin-Agent-Cluster: ?0` 값을 명시합니다.

## X-DNS-Prefetch-Control

### XdnsPrefetchControlOptions (`src/x_dns_prefetch_control/options.rs`)
- `new() -> Self` 기본 정책(`Off`)으로 생성합니다.
- `policy(self, policy: XdnsPrefetchControlPolicy) -> Self` `On/Off` 중 하나를 지정합니다.

### 관련 타입
- `XdnsPrefetchControlPolicy` (enum): `On`, `Off` 값을 가집니다.

## X-Frame-Options

### XFrameOptionsOptions (`src/x_frame_options/options.rs`)
- `new() -> Self` 기본 정책(`Deny`)으로 생성합니다.
- `policy(self, policy: XFrameOptionsPolicy) -> Self` `Deny` 또는 `SameOrigin`을 지정합니다.

### 관련 타입
- `XFrameOptionsPolicy` (enum): `Deny`, `SameOrigin` 값을 가집니다.

## X-Content-Type-Options

- 이 Feature는 옵션 구조체를 제공하지 않으며, 실행 시 항상 `X-Content-Type-Options: nosniff` 헤더를 설정합니다.

## X-Powered-By

- 이 Feature는 옵션 구조체를 제공하지 않으며, 실행 시 `X-Powered-By` 헤더를 제거합니다.
