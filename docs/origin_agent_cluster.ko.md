# Origin-Agent-Cluster

브라우저의 에이전트 클러스터를 출처 단위로 격리합니다. 헤더: `Origin-Agent-Cluster`.

## 옵션 요약
- `?1`(활성) 또는 `?0`(비활성)

## 예시
```rust
use bunner_shield_rs::prelude::*;
let oac = OriginAgentClusterOptions::enable();
let shield = Shield::builder().origin_agent_cluster(oac).build();
```