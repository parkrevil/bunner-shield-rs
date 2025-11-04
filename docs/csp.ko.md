# CSP (Content-Security-Policy)

스크립트·스타일·이미지·프레임 등 외부 리소스 로딩과 실행을 엄격히 제어하는 정책입니다. CSP는 XSS·데이터 주입·위험한 스킴 사용을 줄이는 데 핵심 역할을 하며, 강제 모드 `Content-Security-Policy`와 리포트 전용 `Content-Security-Policy-Report-Only`를 지원합니다.

## 옵션 요약
- 지시문: `default-src`, `script-src`(+ `-elem`, `-attr`), `style-src`(+ `-elem`, `-attr`), `img-src`, `font-src`, `connect-src`, `frame-ancestors`, `object-src`, `base-uri`, `form-action`, `navigate-to`, `manifest-src`, `media-src`, `frame-src`, `worker-src`, `report-to`, `sandbox`, `trusted-types`, `require-trusted-types-for`, `upgrade-insecure-requests`
- 신뢰 토큰: nonce/hash 지원, `strict-dynamic` 지원, 런타임 nonce 매니저로 응답마다 안전한 nonce 자동 주입
- 모드: 강제(기본), 리포트 전용(`.report_only()`)
- 병합/중복 제거: 지시문 병합 시 중복 소스 제거, `report-to`는 FirstWins/LastWins/Union 전략 지원
- 직렬화: 지시문명·토큰 정렬을 통한 안정적·결정적 문자열 출력 보장

## 언제 사용하나요?
- XSS 위협을 낮추고, 스크립트·스타일의 출처·실행 조건을 제한하고 싶을 때
- 서드파티 스크립트 로딩을 엄격히 통제하고, 라이브러리 삽입에 대한 피해 범위를 줄이고 싶을 때
- 점진 도입(Report-Only)으로 위반 케이스를 수집·분석 후 강제 모드로 전환하고 싶을 때

## 동작 방식
각 지시문은 허용된 스킴/호스트/토큰(nonce, hash, 키워드 등)만 로드·실행을 허용합니다.
- nonce: 응답마다 난수가 포함된 `'nonce-…'` 토큰으로 해당 응답의 인라인 스크립트/스타일만 실행 허용
- hash: 인라인 콘텐츠의 해시를 명시해 정확히 일치하는 경우만 허용
- strict-dynamic: 신뢰된 스크립트(예: nonce/해시로 신뢰된)에서 동적으로 로드된 스크립트도 연쇄적으로 신뢰
- trusted-types/require-trusted-types-for: DOM 싱크로 유입되는 문자열을 정책 기반으로 제한

본 라이브러리는 런타임 nonce 모드를 제공하여, 빌더가 플레이스홀더를 삽입하고 실행 시점에 안전한 nonce 값을 발급해 헤더에 렌더링합니다.

## 권장 설정 가이드
- 기본: `default-src 'self'` + `base-uri 'self'` + `object-src 'none'`
- 스크립트: `script-src 'self' 'nonce-…' 'strict-dynamic';` 가능한 경우 호스트 화이트리스트 최소화, `unsafe-inline` 회피
- 스타일: `style-src 'self' 'nonce-…'` 또는 필수 시 일부 호스트만 허용, `unsafe-inline` 지양. 컴포넌트 수준 스타일엔 nonce 활용
- 프레임: `frame-ancestors 'self'` (임베드 차단), 필요한 경우 파트너 도메인만 추가
- 네트워크: `connect-src`에 필요한 API·WS 엔드포인트만 제한 등록
- 마이그레이션: 먼저 Report-Only로 배포하여 위반을 수집·튜닝한 뒤 강제 모드 전환

## 사용 예시
### 1) 최소 안전 기본값
```rust
use bunner_shield_rs::prelude::*;

let csp = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .base_uri([CspSource::SelfKeyword])
        .object_src([CspSource::None]);

let shield = Shield::builder().csp(csp).build();
```

### 2) 런타임 nonce로 스크립트 보호
```rust
use bunner_shield_rs::prelude::*;

let csp = CspOptions::new().script_src(|s| s
        .sources([CspSource::SelfKeyword])
        .runtime_nonce()     // 응답 시점에 안전한 nonce를 자동 발급·주입
        .strict_dynamic()    // 신뢰된 스크립트의 동적 로드 연쇄 신뢰
);

let shield = Shield::builder().csp(csp).build();
let secured = shield.secure(headers)?; // 응답마다 다른 nonce 렌더링
```

### 3) 스타일 nonce/해시 혼합
```rust
use bunner_shield_rs::prelude::*;

let csp = CspOptions::new().style_src(|s| s
        .sources([CspSource::SelfKeyword])
        .runtime_nonce()                 // 인라인 스타일 허용을 nonce로 한정
        .hash(CspHashAlgorithm::Sha256, "BASE64_HASH")
);
```

### 4) Trusted Types 적용
```rust
use bunner_shield_rs::prelude::*;

let policy = TrustedTypesPolicy::new("app")?;
let csp = CspOptions::new()
        .trusted_types(|t| t.policies([policy]).allow_duplicates(false))
        .require_trusted_types_for_scripts();
```

### 5) Report-Only로 점진 도입 + Report-To 병합 전략
```rust
use bunner_shield_rs::prelude::*;

let ro = CspOptions::new()
        .report_only()                          // Report-Only 헤더 사용
        .report_to("csp-errors")               // Report-To 그룹
        .report_to_merge_strategy(ReportToMergeStrategy::Union);

let shield = Shield::builder().csp(ro).build();
```

## API 참고
- 빌더 메서드(일부):
    - 기본 소스: `.default_src([])`
    - 스크립트: `.script_src(|s| s.sources([]).nonce(..).hash(..).runtime_nonce().strict_dynamic())`, `script-src-elem/attr` 지원
    - 스타일: `.style_src(|s| s.sources([]).nonce(..).hash(..).runtime_nonce())`, `style-src-elem/attr` 지원
    - 기타: `.img_src([])`, `.connect_src([])`, `.font_src([])`, `.frame_ancestors([])`, `.object_src([])`, `.base_uri([])`, `.form_action([])`, `.worker_src([])`, `.navigate_to([])` 등
    - Trusted Types: `.trusted_types(|t| ...)`, `.require_trusted_types_for_scripts()`
    - 기타 플래그: `.upgrade_insecure_requests()`, `.sandbox()`, `.sandbox_with([...])`
    - 리포트: `.report_to("group")`, `.report_only()`
    - 병합: `.merge(&other)`, `report_to_merge_strategy(FirstWins|LastWins|Union)`
- Nonce 유틸: `CspNonceManager::new().issue_header_value()`, `CspOptions::generate_nonce()`
- 직렬화: 안정적 정렬·중복 제거 보장, 헤더 문자열 결정적 생성

## 유효성 검사와 경고
- 본 라이브러리는 검증 시 경고를 제공합니다.
    - 위험 스킴(data:, blob:, filesystem:) 사용 경고(지시문별 심각도 다름)
    - `worker-src` 미지정 시의 폴백 검토: `default-src`가 과도히 관대하면 경고, 전반 부재 시 치명 경고
- 빈/허용 범위 과다 지시문, 허용되지 않는 토큰 등은 오류 또는 경고로 안내됩니다.

## 주의 사항 및 한계
- `unsafe-inline`, `unsafe-eval`은 가능한 피하세요. 필요한 경우에도 최소 범위로 제한하고, nonce나 해시로 대체를 우선 고려하세요.
- `data:`·`blob:`·`filesystem:` 스킴은 지시문별로 위험도가 다르며, 특히 스크립트·네비게이션 관련 지시문에서 매우 위험합니다.
- Report-Only는 위반 수집 용도로만 사용되며, 차단 동작은 없습니다. 강제로 전환 시 기능 영향도를 다시 점검하세요.

## 테스트 팁
```rust
use bunner_shield_rs::prelude::*;

let csp = CspOptions::new().script_src(|s| s.sources([CspSource::SelfKeyword]).runtime_nonce());
let shield = Shield::builder().csp(csp).build();
let res = shield.secure(headers)?;
assert!(res.get("Content-Security-Policy").is_some());
```

## FAQ
- Q. nonce와 hash는 무엇을 선택해야 하나요?
    - A. 동적으로 변하는 인라인 스크립트엔 nonce가 적합합니다. 정적 인라인 콘텐츠는 해시가 관리 용이할 수 있습니다.
- Q. strict-dynamic을 써야 하나요?
    - A. 서드파티 로더가 추가 스크립트를 불러오는 구조라면 nonce/해시와 함께 `strict-dynamic`을 고려하세요.
- Q. Report-Only에서 관찰만 하려면?
    - A. `.report_only()`로 전환하고 Report-To 그룹을 지정한 뒤 수집·튜닝 후 강제 모드로 전환하세요.