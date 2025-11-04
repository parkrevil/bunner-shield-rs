# X-DNS-Prefetch-Control

DNS 프리페치 동작을 제어합니다. 값: `on` 또는 `off`.

## 옵션 요약
- 기본값: `off` (프라이버시 우선)
- `on`: 브라우저가 링크된 도메인의 DNS를 미리 조회하여 탐색 성능을 향상할 수 있습니다.
- `off`: DNS 노출을 줄이고 불필요한 사전 조회를 방지합니다.

## 예시
```rust
use bunner_shield_rs::prelude::*;
use bunner_shield_rs::x_dns_prefetch_control::XdnsPrefetchControlPolicy as P;

// 기본 off
let xdns = XdnsPrefetchControlOptions::new();
let shield = Shield::builder().x_dns_prefetch_control(xdns).build();

// 성능이 중요한 페이지 일부에서 on 적용
let xdns = XdnsPrefetchControlOptions::new().policy(P::On);
let shield = Shield::builder().x_dns_prefetch_control(xdns).build();
```

## 권장 사항
- 민감/보안 페이지에서는 `off` 유지로 불필요한 DNS 노출을 줄이세요.
- 대량의 외부 링크가 있고 성능 이점이 크다면 제한적으로 `on`을 고려하세요.