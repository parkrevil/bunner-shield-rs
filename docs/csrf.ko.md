# CSRF 보호

더블 서브밋 쿠키 패턴과 HMAC 기반 토큰으로 상태 변경 요청을 보호합니다. 이 라이브러리는 v2 토큰 형식(타임스탬프 포함)과 만료 검증을 기본으로 사용하며, 서버 상태 없이(세션 저장소 없이) 검증할 수 있습니다. 요청에는 `X-CSRF-Token` 헤더가 포함되고, 응답에는 같은 값을 담은 `Set-Cookie`가 내려갑니다.

## 옵션 요약
- 비밀 키: `CsrfOptions::new([u8;32])`로 생성 (필수)
- `origin_validation(use_referer)`로 Origin/Referer 검증
- 재사용 방지 저장소(선택)

## 예시
```rust
use bunner_shield_rs::prelude::*;
let csrf = CsrfOptions::new([0u8; 32])
    .origin_validation(true, true)
    .allowed_origins([
        "https://app.example.com",
        "https://app.example.com:8443",
    ]);

let shield = Shield::builder().csrf(csrf).build();
let secured = shield.secure(headers)?;
assert!(secured.get("X-CSRF-Token").is_some());
```

쿠키는 기본적으로 `__Host-csrf-token` 이름으로 발급되며, `Path=/; Secure; HttpOnly; SameSite=Lax` 속성이 강제됩니다.

## 상세 옵션
- 쿠키 이름: `.cookie_name("__Host-csrf-token")` — 반드시 `__Host-` 접두 필요
- 토큰 길이: `.token_length(32..=64)` — HMAC MAC 길이 축약에 대응하는 보안 등급
- 유효 메서드: `.validate_methods([POST, PUT, PATCH, DELETE])` — 검증 대상 메서드
- 만료: `.token_max_age_secs(7200)` — v2 토큰 만료(기본 2시간)
- 출처 검증: `.origin_validation(enabled, use_referer)` + `.allowed_origins(["https://app.example.com"])`
- 키 로테이션: `.verification_keys(vec![old_key1, old_key2])`

## 언제 사용하나요?
- 폼 제출·API 호출 등 상태를 변경하는 요청 보호가 필요할 때
- 세션 상태를 쓰지 않고(혹은 캐시 친화적으로) CSRF 방어를 구현하고 싶을 때
- 출처 검증(Origin/Referer)까지 병행해 보안을 강화하고 싶을 때

## 동작 방식
1) 발급(issue): 응답 시 토큰을 생성하여
     - 응답 헤더 `X-CSRF-Token`로 노출하고
     - `Set-Cookie: __Host-csrf-token=...; Path=/; Secure; HttpOnly; SameSite=Lax`로 쿠키에 저장합니다.
2) 검증(verify): 상태 변경 메서드(기본 POST/PUT/PATCH/DELETE) 요청에서는 클라이언트가 `X-CSRF-Token` 헤더로 토큰을 되돌려 보내야 하며, 서버는 다음을 확인합니다.
     - HMAC 서명 유효성(필수)
     - v2 토큰의 만료 시간(기본 2시간)
     - 선택적으로 Origin/Referer가 허용 목록과 일치하는지

토큰 형식(v2): base64url 인코딩된 바이트 스트림 `[v2][ts(8)][nonce(8)][mac_trunc(n)]`로, MAC은 `HMAC-SHA256(secret, ts||nonce)`입니다. `token_length`는 과거 호환을 위해 32..=64(16..=32바이트 MAC)로 동작합니다.

키 로테이션: `verification_keys`에 과거 키를 등록하면, 발급은 새 키로 하되 검증은 새 키와 과거 키 모두 허용됩니다.

Origin/Referer 검증: `origin_validation(true, use_referer)` 활성화 시, `allowed_origins`에 명시된 정확한 origin(scheme, host, port)이 아니면 차단합니다. Origin이 없고 `use_referer=true`면 Referer로 대체 검증합니다.

주의: 본 라이브러리는 Host 기반 유추를 하지 않으며, 명시적인 `allowed_origins`만 신뢰합니다.

## 권장 설정 가이드
- 쿠키 이름: 기본 `__Host-csrf-token` 유지 — `__Host-` 접두는 보안 속성을 강제합니다.
- 토큰 길이: 64 권장(32바이트 MAC) — 보안 마진 확보
- 만료: 2시간(기본) 또는 트래픽 특성에 맞게 15~120분 범위에서 조정
- 검증 대상 메서드: 기본값 유지 또는 서비스 특성에 맞게 확장/축소
- 출처 검증: 퍼스트파티 앱이라면 활성화를 권장(`use_referer=true` 권장). 허용 origin은 정확히 스킴·포트까지 명시
- 키 로테이션: 새 키를 배포 후 일정 기간 구 키를 `verification_keys`로 유지

## 추가 예시
### 메서드 범위 조정 + 만료 단축
```rust
let csrf = CsrfOptions::new([0u8; 32])
        .validate_methods(["POST", "DELETE"]) // 필요한 메서드만
        .token_max_age_secs(30 * 60);            // 30분
```

### 키 로테이션
```rust
let old = [1u8; 32];
let new = [2u8; 32];
let csrf = CsrfOptions::new(new).verification_keys(vec![old]);
```

## API 참고
- CsrfOptions::new(secret: [u8;32])
- .cookie_name(name) — 반드시 `__Host-`로 시작해야 함
- .token_length(len: usize) — 32..=64
- .validate_methods([&str]) — 검증 대상 HTTP 메서드
- .token_max_age_secs(u64) — 만료 윈도우(초)
- .origin_validation(enabled: bool, use_referer: bool)
- .allowed_origins([&str]) — 스킴·호스트·포트까지 포함
- .verification_keys(Vec<[u8;32]>) — 키 로테이션
- 실행 결과: 응답에 `X-CSRF-Token`, `Set-Cookie: __Host-csrf-token=...; Path=/; Secure; HttpOnly; SameSite=Lax`

## 주의 사항 및 한계
- SameSite=Lax 쿠키만으로 CSRF 완화가 충분하지 않습니다. 토큰·출처 검증과 병행하세요.
- HTTPS가 아닌 환경에서는 `Secure` 쿠키가 적용되지 않습니다. 프로덕션은 반드시 HTTPS에서 사용하세요.
- `allowed_origins`는 정확 일치 매칭입니다. 와일드카드/서브도메인 매칭을 가정하지 마세요.
- 동일 응답에서 토큰을 발급한 직후 바로 사용 검증을 기대하지 마세요. 다음 요청에서 사용하도록 설계하세요.

## 테스트 팁
```rust
let csrf = CsrfOptions::new([0u8; 32]);
let shield = Shield::builder().csrf(csrf).build();
let res = shield.secure(headers)?;
assert!(res.get("X-CSRF-Token").is_some());
assert!(res.get("Set-Cookie").is_some());
```

## FAQ
- Q. Referer는 프라이버시 설정으로 빠질 수 있지 않나요?
    - A. 맞습니다. 그래서 Origin 우선, 없을 때만 Referer 사용을 권장합니다(`use_referer=true`).
- Q. 키 로테이션은 어떻게 하나요?
    - A. 새 키로 생성하고, 검증용 `verification_keys`에 구 키를 추가해 과도기 동안 두 키 모두 허용하세요.
- Q. SPA에서는 어떻게 쓰나요?
    - A. 초기 로드 응답에서 토큰을 세팅한 뒤, 이후 상태 변경 요청마다 `X-CSRF-Token` 헤더로 되보내세요.
- Q. 토큰 재사용 방지도 가능하나요?
    - A. 일반 요청 검증은 만료+서명 검증으로 충분합니다. 특수 흐름에서는 재사용 방지 저장소와 결합한 소비형 검증 패턴을 고려할 수 있습니다.