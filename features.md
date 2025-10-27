# Report-Only 기능 TODO 리스트

## 필수 (우선 도입)

### 공통 기반: Report-Only 모드 인프라
- [ ] `executor.rs`에 `PolicyMode { Enforce, ReportOnly }` 정의
- [ ] 옵션과 헤더 값을 보관하는 `DynamicHeaderCache`(또는 기존 `CachedHeader` 확장) 작성
- [ ] 동적 키를 지원하는 `impl_dynamic_header_executor!` 매크로 추가
- [ ] `executor_test.rs`에 동적 캐시 단위 테스트 작성
- [ ] Report-Only가 필요한 실행기에서 새 매크로를 사용할 수 있도록 공통 헬퍼 공개

### CSP Report-Only 지원
- [ ] `CspOptions`에 `mode: PolicyMode` 필드 추가 (기본값 `Enforce`)
- [ ] `.report_only()` 빌더 메서드 구현 및 체이닝 테스트 작성
- [ ] `Csp::new`에서 모드에 따라 헤더 키 선택하도록 수정
- [ ] `src/csp/executor_test.rs`에 Report-Only 실행 테스트 추가
- [ ] `src/csp/options_test.rs`에 모드 전환 테스트 추가
- [ ] `tests/csp.rs` 통합 테스트에 Report-Only 시나리오 추가

## 선택 (환경/요구에 따라)

### COOP Report-Only
- [ ] `CoopOptions`에 `mode: PolicyMode` 필드 추가
- [ ] `.report_only()` 빌더 메서드 구현
- [ ] `Coop` 실행기를 동적 헤더 매크로로 마이그레이션
- [ ] `src/coop/options_test.rs` 및 `src/coop/executor_test.rs`에 모드 테스트 추가
- [ ] `tests/coop.rs`에 Report-Only 통합 시나리오 추가
- [ ] README/문서에 COOP Report-Only 사용 가이드 추가

### COEP Report-Only
- [ ] `CoepOptions`에 `mode: PolicyMode` 필드 추가
- [ ] `.report_only()` 빌더 메서드 구현
- [ ] `Coep` 실행기를 동적 헤더 매크로로 마이그레이션
- [ ] `src/coep/options_test.rs` 및 `src/coep/executor_test.rs`에 모드 테스트 추가
- [ ] `tests/coep.rs`에 Report-Only 통합 시나리오 추가
- [ ] 문서에 COEP Report-Only 점진 도입 전략 기재

### Permissions-Policy Report-Only
- [ ] `PermissionsPolicyOptions`에 `mode: PolicyMode` 필드 추가
- [ ] `.report_only()` 빌더 메서드 구현 (브라우저 경고 처리 포함)
- [ ] `PermissionsPolicy` 실행기를 동적 헤더 매크로로 마이그레이션
- [ ] 경고/폴백 로직 테스트 (`src/permissions_policy/options_test.rs`, `executor_test.rs`) 추가
- [ ] `tests/permissions_policy.rs`에 Report-Only 통합 시나리오 추가
- [ ] 문서에 브라우저 호환성 및 폴백 전략 업데이트

