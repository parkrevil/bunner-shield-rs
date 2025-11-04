# X-DNS-Prefetch-Control

DNS 프리페치 동작을 제어합니다. `on`/`off`.

## 예시
```rust
use bunner_shield_rs::prelude::*;
let xdns = XdnsPrefetchControlOptions::new();
let shield = Shield::builder().x_dns_prefetch_control(xdns).build();
```