//! HTTP Strict Transport Security (HSTS)
//!
//! 이 모듈은 도메인(및 선택적으로 모든 서브도메인)에 대해 HTTPS만을 강제하는 HSTS 헤더를 제공합니다.
//! 기본값은 `max-age=31536000`(1년)이며, 프리로드(preload) 사용 시 다음을 권장합니다:
//! - includeSubDomains 활성화
//! - max-age는 최소 1년(권장 2년 = 63,072,000초)
//! - 충분한 사전 검증 후 preload 플래그 추가 및 hstspreload.org 제출
//!
//! 더 자세한 가이드는 레포지토리의 `docs/hsts.md`를 참고하세요.

mod executor;
mod options;

pub use executor::Hsts;
pub use options::{HstsOptions, HstsOptionsError};
