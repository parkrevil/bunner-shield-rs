# 안전 헤더 정리 (Safe Headers)

응답 헤더의 키/값을 안전하게 정규화하여 헤더 인젝션·CRLF 주입 등과 같은 취약점을 줄입니다. 이 기능은 내부 `NormalizedHeaders::sanitize_for_http()`를 호출해 유효하지 않은 문자를 제거하고, 다중 값 처리(특히 Set-Cookie)를 표준적으로 정리합니다.

## 무엇을 정리하나요?
- 헤더 값(value)
	- 제어 문자(모든 control, CR/LF 포함)와 공백 문자는 단일 스페이스로 치환합니다.
	- 연속/이질적 공백은 1개 스페이스로 축약됩니다.
- 헤더 이름(name)
	- RFC 토큰 문자가 아닌 문자는 제거합니다: A-Z a-z 0-9 및 ! # $ % & ' * + - . ^ _ ` | ~ 만 허용
	- 정리 결과가 빈 문자열이면 해당 헤더는 제거됩니다.
- 다중 값(Set-Cookie)
	- 단일 문자열 안에 여러 Set-Cookie가 섞여 있는 경우 \n/\r 기준으로 분할합니다.
	- 접두사 "Set-Cookie:"가 붙은 조각은 제거하고 순수 쿠키 문자열로 보관합니다.
	- 결과는 multi-header 모델로 보존되어 재직렬화 시 각 쿠키가 별도 헤더 라인으로 출력됩니다.

## 실행 시점과 효과
- Safe Headers는 다른 보안 기능과 함께 실행되어, 최종적으로 내보낼 헤더 집합을 안전한 형태로 마무리합니다.
- 유효하지 않은 이름의 헤더는 삭제되고, 위험한 값은 무해화되어 전송됩니다.

## 사용 예시
```rust
use bunner_shield_rs::prelude::*;

// 별도 옵션 없음 — 항상 보수적 정리만 수행
let shield = Shield::builder().safe_headers(()).build();
let result = shield.secure(headers)?;

// 필요 시 multi-header 결과 사용 (예: Set-Cookie 수집)
// let normalized = shield.secure_with_multi(headers)?; // 라이브러리 제공 경로에 맞춰 사용
```

## 주의 사항
- 이름 정리 과정에서 허용되지 않은 문자가 모두 제거되어 빈 이름이 되면 해당 헤더는 드롭됩니다.
- 값의 개행/제어 문자 등이 스페이스로 치환되어 서버가 의도한 비가시 제어가 없어질 수 있습니다. 의도적으로 그런 문자를 보내지 마십시오.
- Set-Cookie는 개행으로 분리되어 각각의 헤더로 직렬화됩니다. 프록시/게이트웨이 호환성이 향상됩니다.