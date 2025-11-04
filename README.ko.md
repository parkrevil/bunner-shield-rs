# bunner-shield-rs 사용 가이드 (한국어)

이 라이브러리는 HTTP 응답 헤더를 안전하게 구성하기 위한 기능 모음입니다. `Shield` 파이프라인에 기능을 등록하고, `secure()` 한 번으로 표준 보안 헤더를 설정합니다.

## 빠른 시작

```rust
use bunner_shield_rs::prelude::*; // 권장: 필요한 타입을 한 번에 임포트

// 1) 기능 옵션 구성
let csp = CspOptions::new()
    .default_src([CspSource::Self_])
    .script_src([CspSource::Self_]);
let rp = ReferrerPolicyOptions::new().strict_origin_when_cross_origin();
let hsts = HstsOptions::new();

// 2) Shield 빌더로 기능 등록 (검증은 secure() 시점에 수행)
let shield = Shield::builder()
    .csp(csp)
    .referrer_policy(rp)
    .hsts(hsts)
    .build();

// 3) 응답 헤더 보강
let mut headers = NormalizedHeaders::new();
let result = shield.secure(&mut headers);
assert!(result.is_ok());
```

- 대부분의 타입은 `prelude`로 임포트하면 편합니다.
- 모든 옵션은 생성 후 `.validate()`로 사전 검증할 수 있으나, `Shield::secure()`가 실행 전에 일괄 검증합니다.

## 기능 목록

각 기능의 상세 문서는 `docs/<기능명>.ko.md` 에 있습니다.

- CSP: `docs/csp.ko.md`
- Permissions-Policy: `docs/permissions_policy.ko.md`
- Referrer-Policy: `docs/referrer_policy.ko.md`
- HSTS: `docs/hsts.ko.md`
- COEP: `docs/coep.ko.md`
- COOP: `docs/coop.ko.md`
- CORP: `docs/corp.ko.md`
- Origin-Agent-Cluster: `docs/origin_agent_cluster.ko.md`
- Fetch Metadata: `docs/fetch_metadata.ko.md`
- CSRF: `docs/csrf.ko.md`
- SameSite 쿠키 업그레이드: `docs/same_site.ko.md`
- X-Content-Type-Options: `docs/x_content_type_options.ko.md`
- X-DNS-Prefetch-Control: `docs/x_dns_prefetch_control.ko.md`
- X-Frame-Options: `docs/x_frame_options.ko.md`
- X-Powered-By 제거: `docs/x_powered_by.ko.md`
- Clear-Site-Data: `docs/clear_site_data.ko.md`
- 안전 헤더 정리(Safe Headers): `docs/safe_headers.ko.md`

팁: 일부 기능은 리포트 전용 모드나 레거시 호환 옵션을 제공합니다. 각 문서를 참고하세요.