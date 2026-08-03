# M8 — 共享最小 TCP/UDP first-match routing

- **Status:** closed
- **Baseline:** `404b62758a191fe879243c755c75bcf8b300040d`
- **Qualified exact:** `926843d61fcfac094765b5d1032b7239e3d9370c`
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

- [x] Legacy和M7 static v1 cohort继续原样有效；routed tagged shape、rule bounds、all tag/
      target/network/final negatives在zero-resource check中fail closed且脱敏。
- [x] 一个shared route interface证明ordered first-match、AND/wildcard、exact target和total
      final；两个binary的TCP/UDP path只消费resolved IDs，不做runtime string lookup。
- [x] Client TCP和同一SOCKS UDP association内的不同targets可选择不同Shadowsocks
      outbounds；response source/session binding、ID collision、bytes、idle和shutdown有界，
      selected failure无fallback。
- [x] Server TCP/UDP在authentication/bounds之后、connect/reserve/commit/send之前逐请求
      选择configured direct identity；cross-inbound UDP binding、replay和response ingress
      ownership保持。
- [x] Existing static/legacy local TCP/UDP/lifecycle回归和bounded routed real-process matrix
      通过；wire、CLI、trace和metric identities不变。
- [x] One exact SHA passes Full、Rust 1.85、three native targets、existing TCP/UDP各
      `12/12`+cleanup、M8 test envelope和blocking review；missing/failed evidence blocks
      close。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M8-T01 | Add the shared route module and validate/compile routed tagged config before side effects | — | done |
| M8-T02 | Route client TCP flows and UDP datagrams across configured Shadowsocks outbounds | M8-T01 | done |
| M8-T03 | Route authenticated server TCP/UDP requests to configured direct identities | M8-T02 | done |
| M8-T04 | Prove routed real-process behavior and qualify one exact SHA | M8-T03 | done |

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

## Close evidence

- Exact `926843d61fcfac094765b5d1032b7239e3d9370c` passed the serial local gate and automatic
  run [`30848182146/1`](https://github.com/zzffu/ferrum2/actions/runs/30848182146)：quality、MSRV、
  Windows/GNU/musl、interop TCP/UDP each `12/12` plus cleanup、Budget、performance regression
  and final qualification all completed successfully。
- A test-only dual-stack echo repair removed Ubuntu resolver-order dependence while preserving the
  `localhost` domain target、case-insensitive `LOCALHOST` matcher and pre-resolution route contract。
  Windows and WSL strict association repeats each passed `10/10`。
- Architect returned `PASS_WITH_NOTES` and terminal QA returned `PASS`；blocking findings are zero。
  Budget passed at growth `837/840` with remaining `3`。Performance supplied only regression and
  aggregate-dependency evidence；M8 makes no performance threshold or claim。
- All four tickets and all six exit criteria are complete。The authorized non-force pushes are
  consumed；no rerun、further push、PR、tag、release or publication is authorized。See the
  [M8 handoff](../handoffs/HANDOFF-M8-2026-08-04.md)。
