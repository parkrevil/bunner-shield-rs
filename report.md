# bunner-shield-rs TODO 목록

> 마지막 업데이트: 2025-10-31

## 0) 즉시 해결 — Critical
- [ ] CSRF: `Csrf` executor에 검증 로직 추가 (요청별 토큰 검증)
- [ ] CSRF: `X-CSRF-Token` 헤더 검증(POST/PUT/DELETE)
- [ ] CSRF: 요청/응답 컨텍스트 분리(요청 검증/응답 설정 인터페이스)
- [ ] CSRF: `HmacCsrfService::verify` 만료 시간 검증 기본화
- [ ] CSRF: `CsrfReplayStore` 기본 구현체 제공(메모리/Redis)
- [ ] Set-Cookie: `NormalizedHeaders::into_result()` 재설계(다중 헤더)
- [ ] Set-Cookie: `HashMap<String, Vec<String>>` 또는 동등 API로 반환
- [ ] Set-Cookie: `get_cookies() -> Vec<String>` 등 전용 접근자 제공
- [ ] Set-Cookie: 통합 테스트 수정(개행 기반 제거)
- [ ] 요청/응답 분리: `Shield::secure()` 주의사항 및 필터링 헬퍼 제공

## 1) 표준 준수 및 기능
- [ ] Referrer-Policy: 다중 정책 지원(`Vec<ReferrerPolicyValue>`), 직렬화 시 쉼표 연결, 단일 정책 편의 메서드 유지
- [ ] Permissions-Policy: Origin 직렬화 정책 적용(비키워드=항상 인용, 정규화, 레거시 토글 옵션)
- [ ] HSTS: `preload` 권장 2년 문서화 및 정책 가이드

## 2) 보안 설계·아키텍처
- [ ] CSRF: 정적 허용 출처 목록(`allowed_origins`) 추가 및 `Host` 기반 제거
- [ ] CSRF: Stateless 토큰 nonce — 영구 저장소 옵션 또는 랜덤 nonce 권장
- [ ] CSRF: `verify()` 기본 동작에 만료 포함, `verify_signature_only()` 분리, `now_secs` 내부 계산
- [ ] Fetch Metadata: 프레임워크 통합 가이드(Axum/Actix), 위반 시 응답 전략(403/500) 문서화, Observability 가이드
- [ ] Fetch Metadata: 정책 위반 훅 `on_violation` 옵션 제공
- [ ] SafeHeaders: 이름 재고(`HeaderSanitizer`/`HttpHeaderValidator`), Rustdoc에 방어 범위 설명, 기본 활성화 여부 명시

## 3) API 설계·DX
- [ ] Shield 빌더: 검증을 `secure()`로 지연, 메서드 `Self` 반환, `build()` 단계 옵션
- [ ] 에러 타입: 공통 `ShieldError`로 통합 또는 카테고리 그룹핑, `source()` 체인 유지
- [ ] 모듈 구조: 복잡 모듈 구조 정당성 문서 또는 평탄화 검토
- [ ] 공개 API 최소화: `lib.rs` 최상위 노출 축소, `prelude` 검토
- [ ] 추상화 수준: 정적 헤더 단순 함수화, 동적 기능만 트레이트, 매크로 사용 최소화/예시 문서화
- [ ] SameSite: 쿠키 이름별 정책 맵, Path/Domain/Max-Age 속성 강제 옵션
- [ ] NormalizedHeaders: 파이프라인 정렬 최적화(BinaryHeap 등) 또는 정렬 상태 보장

## 4) 문서·예제
- [ ] Rustdoc: 공개 API 주석, 모듈별 위협 설명, 예제 추가, `cargo doc --open` 검증
- [ ] examples/: Axum, Actix-web, Rocket 예제, SPA/API/정적 사이트 권장 설정
- [ ] README.md: 개요, 빠른 시작, 주요 기능, 라이선스/기여 가이드
- [ ] docs/: 아키텍처 설명, 보안 모범 사례, 마이그레이션 가이드
- [ ] X-Frame-Options: `ALLOW-FROM` 미지원 명시 및 CSP `frame-ancestors` 권장 안내 추가

## 5) 성능·의존성
- [ ] Feature flags: `csrf` 기능 분리, 기본 빌드 제외, 사용법 문서화
- [ ] 의존성: `url` 크레이트 최소화(수동 파싱 대체 또는 `csrf` feature 한정)

## 6) 테스트·CI
- [ ] 커버리지: `tarpaulin`/`llvm-cov` 통합, 80% 목표, 공격 시나리오 테스트
- [ ] Proptest: 전략 확대, 경계값/에러 케이스 그룹 강화
- [ ] CI: GitHub Actions — 빌드/테스트/린트/문서/보안 스캔/커버리지 리포트 자동화

## 7) 메타·문서 보완
- [ ] PolicyMode/Report-Only 지원 범위 문서화(기능별 지원/한계/Chromium 주석)
- [ ] `Infallible` 옵션 사용 항목의 향후 검증 전략(공통 에러·선택 트레이트) 정리
