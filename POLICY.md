# 보안 기능 계획서

## Express Helmet 기능 목록

### 1. Content Security Policy (CSP)
설명: 리소스 로딩을 제어하여 XSS 및 데이터 유출을 방지하는 핵심 정책
국제 표준:
 - W3C CSP Level 3
 - OWASP Top 10 (A03:2021 - Injection)
 - Google Strict CSP (현대적 접근법)

주요 디렉티브:
- default-src, script-src, style-src, img-src, connect-src, font-src, object-src, media-src
- child-src, worker-src, frame-src, frame-ancestors ⭐ (X-Frame-Options 대체)
- base-uri, form-action ⭐, manifest-src (웹 앱 매니페스트)
- upgrade-insecure-requests, sandbox
- script-src-elem/style-src-elem, script-src-attr/style-src-attr (세분화)
- require-trusted-types-for 'script', trusted-types (Chrome)

보고/모니터링:
- report-to (권장)
- report-uri (⚠️ 폐기 예정, 레거시 호환)

배포 전략:
- Content-Security-Policy (강제)
- Content-Security-Policy-Report-Only (모니터링) ⭐

⚠️ 중요 구현 지침:
- 프로덕션 전 반드시 Report-Only로 충분히 관찰 후 강제 전환
- report-to 우선 사용, frame-ancestors로 X-Frame-Options 대체

 예시(강화 정책):
 Content-Security-Policy: script-src 'nonce-<BASE64_NONCE>' 'strict-dynamic'; object-src 'none'; base-uri 'none';
🔴 1단계 기본 정책 예시:
default-src 'self';
img-src 'self';
font-src 'self';
connect-src 'self';
frame-ancestors 'self';
base-uri 'self';   
form-action 'self';
object-src 'none';
upgrade-insecure-requests;

🟡 2단계 Strict CSP (인라인 방어):
script-src 'nonce-<BASE64_NONCE>' 'strict-dynamic';
style-src 'nonce-<BASE64_NONCE>';
object-src 'none';
base-uri 'none';

---

### 2. X-DNS-Prefetch-Control
설명: DNS 프리페치 허용/차단으로 프라이버시/성능 균형 제어
국제 표준: OWASP Secure Headers Project, HTML dns-prefetch 힌트
주요 옵션: allow: 'on' | 'off' (기본 off 권장)
우선순위: 🟡 선택 (2–3단계)

---

### 3. X-Frame-Options (레거시)
설명: 클릭재킹 방지 (레거시). CSP의 frame-ancestors로 대체 권장
국제 표준: RFC 7034
주요 옵션: DENY | SAMEORIGIN (ALLOW-FROM는 비권장/비표준)
우선순위: 🟡 호환성용 (2단계)

---

### 4. X-Powered-By (제거)
설명: 기술 스택 노출 차단을 위해 항상 제거
국제 표준: OWASP ASVS 4.0 (V14.5), CWE-200
우선순위: 🔴 필수 (1단계)

---

### 5. Strict-Transport-Security (HSTS)
설명: HTTPS 강제 및 중간자 공격 방지
국제 표준: RFC 6797, PCI DSS
주요 옵션: max-age, includeSubDomains, preload
우선순위: 🔴 필수 (1단계)
⚠️ 가이드: 프리로드 시 max-age ≥ 31536000, includeSubDomains, preload를 설정하고 hstspreload.org로 등록 검토

---

### 6. X-Download-Options
설명: IE에서 다운로드한 파일의 실행 방지 (noopen)
국제 표준: OWASP Secure Headers, IE 전용 동작
주요 옵션: noopen
우선순위: 🟡 권장 (2단계)

---

### 7. X-Content-Type-Options
설명: MIME 타입 스니핑 방지
국제 표준: OWASP Secure Headers Project
주요 옵션: nosniff
우선순위: 🔴 필수 (1단계)

---

### 8. Origin-Agent-Cluster
설명: 오리진 단위 에이전트 클러스터 격리로 사이드 채널 위험 완화
국제 표준: WHATWG HTML Standard
주요 옵션: ?1 (격리 활성)
우선순위: 🟡 권장 (2단계)

---

### 9. X-Permitted-Cross-Domain-Policies
설명: Adobe Flash/Acrobat 등에서 사용하는 교차 도메인 정책 제어
국제 표준: Adobe Cross-Domain Policy Spec, OWASP Secure Headers
주요 옵션: none | master-only | by-content-type | all
우선순위: 🟡 권장 (2단계)

---

### 10. Referrer-Policy
설명: Referer(Referrer) 헤더의 전송 범위 제어
국제 표준: W3C Referrer Policy, GDPR 고려
주요 옵션: no-referrer | same-origin | origin | strict-origin | origin-when-cross-origin | strict-origin-when-cross-origin | no-referrer-when-downgrade | unsafe-url
권장 기본값: strict-origin-when-cross-origin
우선순위: 🟡 권장 (2단계)

---

### 11. Cross-Origin-Embedder-Policy (COEP)
설명: 문서에 임베드되는 크로스 오리진 리소스는 명시적으로 허용(CORP/CORS)되어야 함
국제 표준: WHATWG Fetch/HTML
주요 옵션: require-corp | credentialless
우선순위: 🔴 필수 (1단계)
주의: credentialless는 인증/캐시 동작에 영향 → 점진 도입 권장

---

### 12. Cross-Origin-Opener-Policy (COOP)
설명: 윈도우/탭 간 교차 오리진 상호작용 차단으로 프로세스 격리
국제 표준: WHATWG HTML
주요 옵션: unsafe-none | same-origin-allow-popups | same-origin(권장)
우선순위: 🔴 필수 (1단계)

---

### 13. Cross-Origin-Resource-Policy (CORP)
설명: 리소스를 어느 오리진에서 가져갈 수 있는지 선언
국제 표준: WHATWG Fetch, OWASP Secure Headers
주요 옵션: same-origin(권장) | same-site | cross-origin
우선순위: 🔴 필수 (1단계)

---

### 14. Permissions-Policy (선택)
설명: 브라우저 기능(센서, 카메라 등) 사용 권한을 출처별로 제어
국제 표준: WICG Permissions Policy
예시: geolocation=(self), camera=()
우선순위: 🟡 권장 (2–3단계)
비고: Feature-Policy의 계승 규격으로 브라우저 간 구문/지원 편차가 있습니다

---

### 15. Clear-Site-Data (선택)
설명: 로그아웃/계정 삭제/보안 사고 대응 시 클라이언트 상태(캐시/쿠키/스토리지/실행 컨텍스트) 정리
국제 표준: W3C Clear Site Data
디렉티브: "cache", "cookies", "storage", "executionContexts" (조합 가능)
우선순위: 🟡/🟢 선택 (2–3단계)
주의: "cookies" 사용 시 사이트 쿠키 전체 삭제로 세션/SSO에 영향. 적용 범위와 타이밍을 신중히 설계

---

## CSRF (Cross-Site Request Forgery) 보호

핵심 개념: 토큰 생성/검증을 중심으로 Double Submit Cookie, SameSite, 출처 검증을 조합한 다층 방어

### 1. CSRF 토큰 생성 및 검증 (핵심)
설명: 요청마다(또는 세션 단위) 고유한 토큰을 생성/검증하여 위조 요청 차단
국제 표준: OWASP Top 10, OWASP CSRF Cheat Sheet, CWE-352
주요 기능:
- 토큰 검증: 쿠키 vs 헤더/바디 비교
주요 옵션: sessionKey, value, ignoreMethods (GET/HEAD/OPTIONS)
우선순위: 🔴 필수 (1단계)
권장: 로그인/권한 상승/세션 갱신 시 토큰 회전(rotate)으로 재사용 공격 표면 축소

### 2. Double Submit Cookie 패턴
설명: 쿠키의 토큰과 요청의 토큰을 비교해 검증
국제 표준: OWASP CSRF Cheat Sheet, RFC 6265
구현:
1) 서버가 토큰을 생성해 쿠키로 전송 2) 클라이언트가 헤더/바디에 토큰 반영 3) 서버가 일치 여부 검증
주요 옵션:
- cookie.httpOnly: false (⚠️ 예외; 클라이언트가 읽어야 함)
- cookie.secure: true (HTTPS 전용)
- cookie.sameSite: Lax 권장(Strict는 일부 리디렉트/결제/SSO 흐름과 충돌 가능)
- cookie.signed, cookie.maxAge
보안 주의:
- CSRF 토큰 쿠키는 HttpOnly=false이므로 XSS 표면이 존재합니다 → 엄격한 CSP, 입력 검증, 짧은 TTL, 토큰 회전으로 완화하세요
이름 접두사 권장:
- __Host-: Secure 필수, Path=/ 필수, Domain 지정 금지, HTTPS 오리진에서만 설정 가능
- __Secure-: Secure 필수, Path/Domain 지정 가능
우선순위: 🔴 필수 (1단계)

### 3. SameSite Cookie 속성 (필수)
설명: 크로스 사이트 요청 시 쿠키 전송 제한으로 CSRF 위험 대폭 축소
국제 표준: RFC 6265bis, OWASP Session Management
옵션: Strict | Lax(기본 권장) | None(반드시 Secure)
지침:
- 가능한 모든 쿠키의 기본값은 Lax로 설정. Strict는 매우 보수적이라 일부 정상 흐름을 끊을 수 있음
- 세션 쿠키: Lax 권장
- CSRF 토큰 쿠키: Lax 또는 Strict
- None은 반드시 Secure와 함께 사용하며, 크로스사이트 임베드/인증이 필요한 특정 시나리오에서만 제한적으로 사용
우선순위: 🔴 필수 (1단계)
경고: CSRF 토큰 쿠키만 HttpOnly=false 허용(민감정보 저장 금지). 로그인/권한상승/세션갱신 시 토큰 회전 권장, 가능하면 __Host- 접두사 사용

### 4. Origin 및 Referer 검증
설명: 요청 출처를 검증하는 추가 방어 레이어
국제 표준: OWASP CSRF Cheat Sheet, RFC 6454
우선순위: 🟡 권장 (2단계)

### 5. Custom Request Headers (API)
설명: 커스텀 헤더 요구로 CORS 프리플라이트를 유도하여 위조 요청 차단
국제 표준: OWASP CSRF Cheat Sheet
우선순위: 🟡 권장 (2단계)

---

규정: GDPR, PCI DSS, ISO/IEC 27001, SOC 2

---

## 구현 우선순위

1단계 (필수):
- HSTS, CSP 기본+Report-Only, X-Content-Type-Options, X-Powered-By 제거
- CSRF 토큰, SameSite, COEP, COOP, CORP

2단계 (강력 권장):
- Strict CSP(nonce/hash), X-Frame-Options(호환), Referrer-Policy(기본: strict-origin-when-cross-origin)
- Origin-Agent-Cluster, X-Download-Options, X-Permitted-Cross-Domain-Policies
- Permissions-Policy(필요시)

3단계 (선택):
- X-DNS-Prefetch-Control, CSP 세밀 튜닝

구현 원칙/주의: CSP frame-ancestors 우선, report-to 우선; COEP/COOP/CORP 함께 운영; CSRF 토큰 쿠키만 HttpOnly 예외; 레거시 report-uri는 폴백

---
CSP 배포 전략:
1) Report-Only → 2) 강제 전환 → 3) Strict CSP 추가 → 4) Strict 강제 → 5) 세밀화

CSRF 방어 계층:
1) 토큰 검증(핵심) → 2) SameSite 쿠키 → 3) Origin/Referer 검증 → 4) 커스텀 헤더(API)

---

## 부록: Helmet 매핑

- contentSecurityPolicy → Content-Security-Policy / -Report-Only
- dnsPrefetchControl → X-DNS-Prefetch-Control
- frameguard → X-Frame-Options
- hidePoweredBy → X-Powered-By 제거
- hsts → Strict-Transport-Security
- ieNoOpen → X-Download-Options
- noSniff → X-Content-Type-Options
- originAgentCluster → Origin-Agent-Cluster
- permittedCrossDomainPolicies → X-Permitted-Cross-Domain-Policies
- referrerPolicy → Referrer-Policy
- crossOriginEmbedderPolicy → Cross-Origin-Embedder-Policy
- crossOriginOpenerPolicy → Cross-Origin-Opener-Policy
- crossOriginResourcePolicy → Cross-Origin-Resource-Policy
- permissionsPolicy (별도 미들웨어일 수 있음) → Permissions-Policy

---

## 참고 문헌

보안/가이드:
- OWASP Top 10: https://owasp.org/Top10/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- OWASP CSRF Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

CSP:
- W3C CSP Level 3: https://www.w3.org/TR/CSP3/
- Google Strict CSP: https://csp.withgoogle.com/docs/strict-csp.html
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- MDN CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

헤더/쿠키 표준:
- RFC 6797 (HSTS): https://www.rfc-editor.org/rfc/rfc6797
- RFC 7034 (X-Frame-Options): https://www.rfc-editor.org/rfc/rfc7034
- RFC 6265bis (Cookies): https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

기타:
- Permissions Policy: https://w3c.github.io/webappsec-permissions-policy/
- Reporting API: https://www.w3.org/TR/reporting-1/
- MIME Sniffing Standard: https://mimesniff.spec.whatwg.org/
