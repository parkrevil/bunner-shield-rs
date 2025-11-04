# Origin-Agent-Cluster

문서, 워커, 스크립트 등이 공유하는 브라우저 “에이전트 클러스터”를 출처(Origin) 단위로 격리합니다. 헤더: `Origin-Agent-Cluster`.

효과
- 동일 사이트 내 다른 출처와 격리가 강화되어, 크로스 오리진 간 공유 객체/캐시/워커 간섭 가능성을 낮춥니다.
- COOP/COEP와 함께 사용 시 강한 격리 모델을 구성합니다.

## 옵션
- `enable()` → `?1` 전송(기본값): 출처 단위 클러스터 격리 활성화
- `disable()` → `?0` 전송: 비활성화(호환성 문제 시 선택)

브라우저 예시 헤더
- `Origin-Agent-Cluster: ?1`

## 권장
- 기본 활성화를 권장합니다. 애플리케이션이 동일 사이트 내 타 출처와 워커/캐시를 적극적으로 공유하지 않는 한 부작용이 적습니다.
- 문제 발생 시 해당 영역만 `?0`로 비활성화해 점진 도입하세요.

## 사용 예시
```rust
use bunner_shield_rs::prelude::*;

let oac = OriginAgentClusterOptions::new().enable();
let shield = Shield::builder().origin_agent_cluster(oac).build();
```

## 주의 사항
- 일부 레거시 시나리오에서 shared worker, 캐시 공유 가정이 깨질 수 있습니다.
- OAC는 보안 신호일 뿐 접근 제어를 완전히 대체하지 않습니다. CSP/COOP/COEP/CORS 등과 병행하세요.