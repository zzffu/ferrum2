# SPEC-0010 — M9 multi-upstream 能力边界

- **Status:** Approved
- **Milestone:** M9
- **Baseline:** `5b0a8020e5dac1a915dc64c8229ddd129dd4da4a`
- **Test plan:** `docs/test-plans/TEST-0010-m9-multi-upstream-capability.md`

## Scope

本合同只命名和核验已经交付的 client multi-upstream 行为。它不改变 schema v1、
产品实现、wire、安全或资源语义。

## Requirements

### M9-MUST-01 — multiple concrete upstreams

一个 tagged client document MUST 可包含多个 concrete Shadowsocks-server outbounds；每个
outbound MUST 在 runtime side effect 前解析为 bounded identity，并可由 static binding
或 route rule/final 选择。

### M9-MUST-02 — real TCP/UDP selection

同一 client process MUST 能让真实 TCP flows 使用不同 upstream。Routed UDP MUST 可在
同一 SOCKS UDP association 内按每个 validated datagram 的 target 选择不同 upstream，
且 response MUST 由所选 endpoint 的 protocol leg 验证。

### M9-MUST-03 — deterministic failure boundary

一次选择 MUST 只得到一个 concrete outbound。Selected upstream failure MUST NOT 自动
尝试 sibling、later rule 或 final；现有 authentication、replay、source binding、bounds、
lifecycle 和 observability MUST 保持。

### M9-MUST-04 — zero-code closure

若 M7/M8 的实现和资格证据满足以上 MUST，M9 MUST 以零 product/test code 关闭。
Upstream group 只有在出现需要自动成员选择的独立可观察需求后才可另立合同。

## Non-goals

- Upstream group、load balancing、health check、fallback/failover、chaining 或 retry。
- Per-upstream credentials、quota、DNS/Geo/user policy 或 new endpoint kind。
- 新配置、trait、dependency、test helper、remote qualification 或 performance claim。
