# 보안 헤더 라이브러리 표준 준수 분석 보고서

## 1. Content-Security-Policy (CSP)

#### ❌ 누락된 기능

##### 1. CSP Level 3 고급 기능
- webrtc 디렉티브
- navigate-to 디렉티브
- worker-src 폴백 체인 검증 부재

##### 2. 보안 관련 누락 사항
- 'strict-dynamic' 호환성 검증 없음
- CSP 디렉티브 우선순위 검증 없음
- 자동 Nonce 로테이션 부재
- 레거시 report-uri 디렉티브는 의도적으로 미지원 (사양 폐기)

##### 3. DX 관련 누락
- 사전 정의된 정책 템플릿 부재
- 디렉티브 자동완성/타입 안전성 부재 (문자열 기반)
- 정책 시뮬레이션 모드 부재

### 개선 권장사항

#### 우선순위 높음
1. 디렉티브 열거형 타입화 도입 (`Directive` enum)

#### 우선순위 중간
3. worker-src 폴백 로직 검증
4. strict-dynamic 호환성 경고 추가

#### 우선순위 낮음
5. webrtc/navigate-to 옵션 제공 (브라우저 지원 제한)

---

## 2. Strict-Transport-Security (HSTS)

#### ⚠️ 경미한 누락 사항
- 권장 최소 max-age(6개월) 미만 설정 시 경고 없음
- max-age=0 비활성화를 위한 명시적 메서드 없음 (`disable()`)

### 개선 권장사항
- `validate()`에서 권장치 미만 경고 로그 추가
- `HstsOptions::disable()` 유틸 메서드 추가

---

## 7. X-Frame-Options

#### ❌ 누락된 기능 (및 이슈)
- ALLOW-FROM: 명세에는 있으나 브라우저 미지원 (배제 정당)
- CSP frame-ancestors와 중복 설정 시 우선순위/마이그레이션 안내 부족

### 개선 권장사항 (우선순위 중간)
2. 사용 시 CSP 권장 로그(경고) 옵션 제공

---

## 10. X-Download-Options

### 개선 권장사항 (우선순위 낮음)
2. 조건부 활성화 옵션 제공(기본 비활성화 고려)

---

## 11. X-Permitted-Cross-Domain-Policies

### 개선 권장사항 (우선순위 낮음)
2. 조건부 활성화 옵션 제공(기본 비활성화 고려)

---

## 12. Permissions-Policy

#### ❌ 누락된 기능/문제
- 디렉티브 타입화 부재 (enum 없음)
- 허용 리스트 구조화 부재 (`self`, `src`, 출처 리스트 문자열 처리)
- 형식 검증 부재 (디렉티브/값)
- Feature-Policy 병행 지원 부재 (레거시 호환 낮음)
- DX 템플릿/디렉티브별 메서드 부재

### 개선 권장사항
- 디렉티브 열거형/허용 리스트 타입 도입, 형식 검증 강화
- Feature-Policy 병행 생성 옵션 제공
- 사전 정의 정책 템플릿(`restrictive()`, `permissive()`) 제공

---

## 13. Clear-Site-Data

#### ⚠️ 경미한 누락 사항
- "*" (wildcard) 전부 삭제 값 미지원

### 개선 권장사항 (우선순위 중간)
- `all()` 메서드로 `"*"` 지원 추가

---

## 16. CSRF 보호

#### ❌ 누락된 기능/문제
- 토큰 검증 메서드 부재 (`verify_token()`)
- HMAC 검증 부재 및 상수 시간 비교 미적용
- SameSite 통합 부족, Double Submit Cookie 비교 로직 부재
- 요청별 토큰 로테이션 및 토큰 만료 부재

### 개선 권장사항 (우선순위 높음)
1. `verify()` 검증 메서드 추가 (상수 시간 비교 적용)
2. HMAC 기반 무결성 검증
3. SameSite 자동 통합 (Strict/Lax)
4. 토큰 만료 및 로테이션 지원

---

## 18. 누락된 보안 헤더

### 1. X-XSS-Protection
- 상태: 구현 안 됨 (Deprecated) → CSP 사용 권장, 구현 불필요

### 2. Expect-CT
- 상태: 구현 안 됨 (Deprecated) → 브라우저 내장 CT, 구현 불필요

### 3. NEL (Network Error Logging)
- 상태: 구현 안 됨 (필요성 중간) → Reporting API 일부, 향후 고려

### 4. Report-To
- 상태: 부분 구현 → 독립 `Report-To` 헤더 기능 구현 필요

### 5. Timing-Allow-Origin
- 상태: 구현 안 됨 (필요성 중간) → 선택적 구현 고려

### 6. Accept-CH (Client Hints)
- 상태: 구현 안 됨 (필요성 낮음) → 표준 안정 후 재검토
