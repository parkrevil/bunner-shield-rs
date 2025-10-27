# 남은 기능 목록 (Roadmap)

본 문서는 현재 라이브러리에 미구현이거나 범위 밖으로 남아있는 보안 기능을 정리합니다. 우선순위는 "필수(우선 도입)"와 "선택(환경/요구에 따라)"로 구분합니다. 폐기(Deprecated) 항목은 명시적 비대상으로 둡니다.

## 필수 (우선 도입)

### CSP Report-Only 지원
- 헤더: `Content-Security-Policy-Report-Only`
- 목적: 운영 전 탐지·튜닝. 서비스 중단 없이 정책 위반 관찰.

## 선택 (환경/요구에 따라)

### COOP/COEP Report-Only
- 헤더: `Cross-Origin-Opener-Policy-Report-Only`, `Cross-Origin-Embedder-Policy-Report-Only`.
- 목적: 점진적 도입/모니터링.

### Permissions-Policy Report-Only
- 지원 현황/브라우저 호환성 확인 후 선택 도입.

