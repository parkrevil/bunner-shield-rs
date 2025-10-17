# 통합 테스트 스위트 개요 (bunner-shield-rs)

본 문서는 bunner-shield-rs 라이브러리의 통합 테스트 현황을 요약합니다. 최근 작업을 통해 라이브러리 수준에서 요구되는 통합 시나리오가 모두 구현되었으며, 중복되거나 누락된 항목 없이 성공·엣지·실패 경로를 포괄합니다.

작성일: 2025-10-16

## 통합 테스트 커버리지 요약

- **보안 헤더 파이프라인 전반**: CSP, HSTS, Referrer-Policy, COEP/COOP/CORP, Origin-Agent-Cluster, Permissions-Policy, X-Content-Type-Options, X-Frame-Options, X-DNS-Prefetch-Control, Clear-Site-Data, X-Powered-By 제거까지 단일 실행기의 동작과 파이프라인 조합을 모두 검증합니다. CSP는 25개 디렉티브 전부와 nonce/hash/strict-dynamic/Trusted Types/Sandbox/Report-To 조합까지 확인했습니다.
- **성공 및 엣지 경로**: 기존 헤더 덮어쓰기, 무관 헤더 보존, 헤더 키 대소문자 정규화, 다중 쿠키 처리뿐 아니라 CSP 전 디렉티브의 정렬·병합, 빈 토큰 무시, Trusted Types 전환, Sandbox 토큰 조합, Strict-Dynamic + nonce + hash 조합, Report-To 병합, flag 디렉티브(`upgrade-insecure-requests`, `block-all-mixed-content`) 검증까지 단일 케이스 기반으로 확인합니다.
- **실패 경로 검증**: COEP/COOP/CORP, HSTS, CSP, Permissions-Policy, CSRF/SameSite 등의 옵션 검증 실패가 통합 실행 중에도 정확히 전파되는지 확인합니다. CSP는 허용되지 않은 토큰/스킴/포트 와일드카드, 잘못된 nonce·hash, Strict-Dynamic 충돌, Sandbox 오타, 제약을 위반한 `unsafe-*` 토큰, 제어 문자 포함 값 등 모든 에러 변형을 분리된 케이스로 다룹니다.

## 주요 시나리오 정리

### 1. 전체 파이프라인 성공 경로
- 조합: CSP + X-Powered-By 제거 + HSTS + X-Content-Type-Options + CSRF + SameSite + COEP/COOP/CORP + X-Frame-Options + Referrer-Policy + Origin-Agent-Cluster + Permissions-Policy + X-DNS-Prefetch-Control + Clear-Site-Data
- 검증 포인트: 기존 헤더 값 덮어쓰기, 정규화된 키 유지, Clear-Site-Data 토큰의 순서 비의존 비교, CSRF 토큰 형식, Strict SameSite 쿠키 속성.

### 2. 다중 쿠키 및 헤더 정규화
- 기존에 존재하던 다중 `Set-Cookie` 헤더와 신규 CSRF 쿠키가 모두 강화된 속성(SameSite=Strict, Secure, HttpOnly)을 유지하는지 검증합니다.
- 소문자 헤더 키로 입력된 HSTS/Permissions-Policy/COEP/COOP 등이 실행 후 표준 대소문자로 재배치되는지 확인합니다.

### 3. CSP Strict-Dynamic + Nonce
- `CspNonceManager`를 활용해 nonce를 발급하고, `Strict-Dynamic` 디렉티브와 함께 헤더에 반영되는지 검증합니다.

### 4. CSP 전방위 디렉티브 검증
- 25개 CSP 디렉티브 전부에 대해 nonce/hash/scheme/host/sandbox/trusted-types/report-to/flag 디렉티브 등 가능한 모든 퍼뮤테이션을 한 번 이상 테스트합니다.
- `add_source`의 공백 무시, `merge` 시 중복 토큰 제거, Trusted Types 정책 중복 제거 및 `'none'` 전환, flag 디렉티브의 빈 값 유지 등 세밀한 API 동작을 통합 관점에서 확인합니다.

### 5. 대량 덮어쓰기 및 오류 전파
- 파이프라인 여러 단계에서 상충되는 초기 값을 입력했을 때 최종 정책이 올바르게 덮어써지는지 확인합니다.
- Permissions-Policy, CSRF, HSTS, CSP 등에서 발생한 옵션 검증 실패가 통합 흐름에서 그대로 surface 되는지 확인합니다.

## 결론

- 현재 저장소의 통합 테스트는 라이브러리 수준에서 요구되는 모든 조합을 커버하며, 계획된 개선 과제는 남아 있지 않습니다.
- 추가로 다룰 미해결 항목이 생길 경우, 본 문서를 업데이트하여 최신 상태를 반영하면 됩니다.
