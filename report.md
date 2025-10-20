# 작업 TODO (2025-10-20)

- [x] Permissions-Policy: self 토큰 표기 교정
  - 파일: `src/permissions_policy/options.rs`, `src/permissions_policy/options_test.rs`
  - 변경: 빌더 렌더링에서 "'self'"를 self(무따옴표)로 출력하도록 수정. 기존 중복 제거/순서 보존 동작은 유지.
  - 수용 기준:
    - 기존 빌더 스냅샷 테스트 기대값을 self(무따옴표)로 갱신.
    - self 표기 케이스(단독/혼합) 추가 테스트 통과.

- [x] Permissions-Policy: 빌더/검증 최소 강화
  - 파일: `src/permissions_policy/options.rs`, `src/permissions_policy/options_test.rs`
  - 변경: 피처명 공백/빈 문자열 거부, 허용리스트 항목에서 빈/공백만 항목 거부, 에러 문구 명확화.
  - 수용 기준:
    - 빈 피처명/빈 allowlist 항목에 대한 테스트 케이스 추가 및 성공.
    - 기존 정상 케이스(중복 제거·순서 보존) 회귀 없음.

- [x] COOP Executor: 매크로 적용으로 중복 제거
  - 파일: `src/coop/executor.rs`
  - 변경: 수동 FeatureExecutor 구현을 `impl_cached_header_executor!` 매크로로 대체. 동작 동일 유지.
  - 수용 기준:
    - 기존 COOP 단위/통합 테스트 전부 통과.
    - 린트에서 불필요 임포트 경고 없음.

- [x] CSP 직렬화 안정 동작 기본화
  - 파일: `src/csp/options/config/core.rs`(+ 테스트 파일들)
  - 변경: 직렬화 안정 정렬이 옵션이 아닌 기본 동작이 되도록 구현. 외부 패키지 의존 제거/미사용.
  - 수용 기준:
    - 동일 입력 → 동일 헤더 문자열 보장 테스트 추가 및 통과.
    - 기존 API 호환성 및 스냅샷 기대값 유지.

- [x] CSP 병합/메모리 미세 최적화
  - 파일: `src/csp/options/config/core.rs`
  - 변경: report-to Union 및 소스 병합 경로에서 용량 예약/경량 컨테이너 사용으로 할당 감소. 퍼블릭 API/직렬화 결과 불변.
  - 수용 기준:
    - 모든 기존 테스트 통과, 퍼포먼스 회귀 없음(벤치마크는 선택).
