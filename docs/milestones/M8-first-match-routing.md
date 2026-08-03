# M8 — 共享最小 TCP/UDP first-match routing

- **Status:** executing
- **Baseline:** `404b62758a191fe879243c755c75bcf8b300040d`
- **Strategy:** drain
- **Owner:** primary thread

## Outcome

在两个现有 binary 中复用一个有界、纯计算的 first-match route module；routed tagged
配置按 inbound tag、`tcp|udp` 和 exact target 选择 outbound tag，未命中使用唯一
`route.final`。TCP 每 flow 选择一次，UDP 每个已验证 datagram 选择一次；legacy 与 M7
static tagged 行为、SIP022 wire/security、aggregate owners 和 process lifecycle 不变。

## Baseline evidence

- Config：`ClientInboundConfig::outbound` 直接保存 resolved client outbound；
  `ServerInboundConfig::outbound` 保存 direct outbound index，`validate_*_graph` 要求每个
  inbound 一份 static reference。
- Client：`run_with_registry_and_metrics_inner` 按 listener 预建一个
  `ClientOutboundContext`；`client_connection` 在 SOCKS target 解析前已捕获它，
  `prepare_udp_association_with_bind` 在首个 target datagram 前连接唯一 UDP server。
- Server：`run_with_registry` 为每个 listener 捕获一个 `ServerContext::direct`；
  `server_connection` 在 authenticated target 后只打开该 direct。UDP pending request
  已在 commit 前暴露 validated target，但当前没有 route decision。
- Core：`TargetAddr` 已提供 bounded IP/domain+port；尚无 network/route value。Config 已
  依赖 core，两个 binaries 已依赖 config/core，无需新 crate/dependency。

## Assumptions fixed by ADR-0028

- `[route]` 是 additive schema v1 tagged-only mode；缺失时 legacy/M7 static binding exact
  保持。Route mode 与 `inbounds[].outbound` 互斥且必须有 total `route.final`。
- 最多64条有序规则；present matchers按AND，首条命中；exact target包含host+port，
  domain只忽略ASCII大小写，不做DNS-result/CIDR/suffix匹配。
- Shared route module位于 `ferrum2-core`，interface仅返回prevalidated outbound ID；
  config解决tag，binary决定调用时点；不新增trait、factory、registry或dependency。
- TCP route固定到flow；UDP逐datagram route。Selected outbound失败不fallback。
- Routed client UDP复用一个association socket/buffer owner并按实际server endpoint懒建
  bounded protocol leg；static/legacy M6 ownership保持。

## Non-goals

- GeoIP、Geosite、DNS proxy/cache/custom resolver、sniffing或user/multi-user rules。
- CIDR、IP range、domain suffix/keyword/regex、port range/list、negation或rule groups。
- Load balancing、health check、fallback/failover、chaining、multi-hop或outbound groups。
- Per-entry method/PSK、SIP023、新inbound/outbound kind、`Endpoint` interface或hot reload。
- Tag/destination metric labels、management API、performance threshold、package、release、
  publication或任何未单独授权的remote action。

## Exit criteria

- [ ] Legacy和M7 static v1 cohort继续原样有效；routed tagged shape、rule bounds、all tag/
      target/network/final negatives在zero-resource check中fail closed且脱敏。
- [ ] 一个shared route interface证明ordered first-match、AND/wildcard、exact target和total
      final；两个binary的TCP/UDP path只消费resolved IDs，不做runtime string lookup。
- [ ] Client TCP和同一SOCKS UDP association内的不同targets可选择不同Shadowsocks
      outbounds；response source/session binding、ID collision、bytes、idle和shutdown有界，
      selected failure无fallback。
- [ ] Server TCP/UDP在authentication/bounds之后、connect/reserve/commit/send之前逐请求
      选择configured direct identity；cross-inbound UDP binding、replay和response ingress
      ownership保持。
- [ ] Existing static/legacy local TCP/UDP/lifecycle回归和bounded routed real-process matrix
      通过；wire、CLI、trace和metric identities不变。
- [ ] One exact SHA passes Full、Rust 1.85、three native targets、existing TCP/UDP各
      `12/12`+cleanup、M8 test envelope和blocking review；missing/failed evidence blocks
      close。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M8-T01 | Add the shared route module and validate/compile routed tagged config before side effects | — | done |
| M8-T02 | Route client TCP flows and UDP datagrams across configured Shadowsocks outbounds | M8-T01 | done |
| M8-T03 | Route authenticated server TCP/UDP requests to configured direct identities | M8-T02 | done |
| M8-T04 | Prove routed real-process behavior and qualify one exact SHA | M8-T03 | ready |

```text
M8-T01 core/config route contract
  -> M8-T02 highest-risk client TCP/UDP composition
  -> M8-T03 server authenticated TCP/UDP composition
  -> M8-T04 exact-SHA qualification
```

Tickets serialize because T01 temporarily guards routed run mode，T02/T03 remove one role's guard
and share the `config_cli` transition row，and T04 reuses product-owned process harnesses only after
both roles integrate。Product tickets keep workflow files read-only。

## Test envelope

The M8 control policy binds `404b62758a191fe879243c755c75bcf8b300040d` at
code/tests `15529/25482` with `max_test_growth=840` and `ticket_warning=240`。`TEST-0009`
derives 760 lines from its evidence map plus one 80-line contingency；the envelope cannot increase
during M8 execution。

## Blocker / next action

No execution blocker。M8-T01 is integrated at
`876da7e13c37aaf4e316848b13cf0a8f7cb8673b`，M8-T02 at
`ff9070c427bf456edbe3051d4f8781bb65c136c0`，and M8-T03 at
`4a1de3a3183d1235ac3808ae97caebc851f4c2b5`；M8-T04 is the only ready frontier。The M8
Budget is `749/840` with `91` lines remaining，so qualification must reuse compact existing
evidence。Push、hosted run、PR、tag、release and publication remain unauthorized。
