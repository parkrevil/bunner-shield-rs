# Bunner Shield RS 개선 작업 목록 (핵심 보안 방어 중심)

본 문서는 HTTP 보안 방어에 직접 기여하는 “작업 필요 항목”만을 기능별로 재그룹핑해 정리했습니다. 보고/Report 계열과 deprecated 사안은 제외했습니다.

## 공통/인프라

- NormalizedHeaders 다중값 지원 재설계
  - 반환 타입을 다중값을 안전히 표현(예: HashMap<String, Vec<String>> 또는 전용 타입)하도록 교체하여 개행 결합 제거
- 다중값 처리 정책 명시화
  - (필수 범위 최소화) 우선 Set-Cookie 등 안전상 필요한 헤더만 다중값 허용으로 고정
- CRLF(헤더 인젝션) 전역 방어
  - 옵션/빌더/실행기/정규화 경로 전반에서 CR/LF 포함 시 거부하는 공통 유틸 적용
- Set-Cookie 파이프라인 경계 강화
  - 입력에 개행/접두("Set-Cookie:") 혼입 시 명시 거부, 정규화 경로만 다중값 관리

## CSP (Content-Security-Policy)

- 런타임 nonce 경로 안정화
  - runtime_nonce_config 사용부의 expect 제거, 명시적 에러 반환으로 패닉 가능성 제거

## Permissions-Policy

- 입력 검증 강화
  - 기능명·토큰 유효성 강화(제어문자/공백/인젝션 거부)
- CRLF 방어 일원화
  - 정책 문자열 조립 전 공통 검증 유틸 사용

## CSRF
- 키 보호
  - 비밀 키 메모리 zeroize 적용

## 테스트/자동화

- 다중값 헤더 방출 검증
  - 전송 계층에서 반복 헤더로 올바르게 분리 방출되는지 통합 테스트 추가(특히 Set-Cookie)
- CRLF 거부 규칙 회귀 테스트
  - 옵션/빌더/정규화/실행기 전 경로에 대한 인젝션 방어 테스트 포함
 

 
