# M11 — 固定 client proxy chaining 与 per-outbound credentials

- **Status:** planned
- **Baseline:** `7a3c876681255b88492b3608af4fa52497435efc`
- **Strategy:** drain
- **Owner:** primary thread
- **Performance:** required — nested TCP/UDP changes transport hot paths and per-flow/session resource ownership

## Outcome

在 additive schema v1 tagged client graph 上，让每个 concrete Shadowsocks outbound 使用完整的
显式 method/PSK 或继承全局 `[shadowsocks]`，并增加 `2..=8` hop 的固定有序 chain tag。Static
binding、route action 与 manual selector 可选择完整 direct/chain plan；TCP/UDP 逐 hop 使用对应
凭据，任一 hop 失败即终止且不 retry/fallback。既有配置、server global credentials、公开 crypto
seam、SIP022 state machines 与 process lifecycle 保持兼容。

## Baseline evidence

- Config：`ValidatedClientConfig`/`ClientOutboundConfig`仍是global PSK + endpoint-only
  (`crates/ferrum2-config/src/lib.rs:42-65`)；`validate_client_graph`与`validate_route`已在loader内
  完成全部tag/action解析(`:437-884`)，适合在同一zero-resource boundary加入credentials/chains。
- Core：`RouteTable`和selector compiler是唯一static/route/selector选择点
  (`crates/ferrum2-core/src/lib.rs:458-820`)；当前terminal identity仍是单个`usize`。
- TCP：client route后只构造一个`ClientTcpOutbound`(`bins/ferrum2-client/src/run.rs:471-579`)；
  protocol已把connect与request write分成`ConnectedClientOpen` capability
  (`crates/ferrum2-shadowsocks/src/lib.rs:544-699`)。
- UDP：client现在以server endpoint保存single-method leg，并在static setup或每个routed datagram
  选择一次(`bins/ferrum2-client/src/run.rs:658-844,897-1000`)；`UdpClientSession`已提供
  prepare-before-commit response seam(`crates/ferrum2-shadowsocks/src/udp.rs:271-383`)。
- Side effects：`ferrum2-client::main`先`load_client`，`--check-config`在`run`前返回；完整配置
  validation无需新process harness。

## Decisions fixed by ADR-0030

- Root `[shadowsocks]`继续mandatory。Client outbound的`method`/`psk`必须both-or-neither；neither
  继承global，both独立校验。Server继续global-only direct。
- Client-only `[[chains]]`为tagged-only；`1..=64` chains，每条`2..=8` unique concrete hop tags。
  Chain不可嵌套、不可含selector；tag与inbound/outbound/selector共用namespace。
- Direct outbound编译为one-hop plan，chain编译为immutable ordered plan；existing route/selector
  只选择一个plan。Selector可切换整条plan，不修改已snapshot flow/datagram。
- TCP raw-dial first hop，然后在每层authenticated flow内向下一hop写existing SIP022 request；UDP
  由inner到outer encode、由outer到inner authenticate/open，并逐层绑定next-server target。
- All-layer auth/semantic/length checks先于UDP accepted mutation/forwarding；nested wire maximum在
  reservation/session/counter mutation前计算。资源lazy、有界且由既有connection/association owner回收。
- 任一失败no retry、no sibling、no later rule、no final fallback；不增加hop/tag telemetry。

## Non-goals

- Dynamic chain order/membership、selector hop、nested chain、runtime graph rebuild或active connection
  migration/interruption。
- Health check、auto-select、retry、fallback/failover、load balancing或upstream group policy。
- SIP023、多用户、server per-inbound/outbound credentials、quota或external identity lookup。
- DNS/Geo/sniff/user policy、新Endpoint/adapter kind、transparent/TUN、hot reload、management API。
- 新cipher/KDF/protocol core、dependency、unsafe、throughput threshold、package、release或publication。

## Exit criteria

- [ ] Baseline legacy/M7/M8/M10 schema v1 cohort保持exact；partial outbound credential、所有chain
      count/tag/hop/reference/reachability错误在任何网络副作用前closed/redacted fail。
- [ ] Static binding、route rule/final与selector选择完整direct/chain plan；existing direct-only结果
      exact，selector snapshot不被后续switch改写，失败不retry/fallback。
- [ ] Mixed-method/distinct-PSK two-hop TCP按序完成真实echo；每层tamper、wrong credential、later-hop
      failure、half-close/cancel均fail closed并回收完整nested owner。
- [ ] Mixed-method/distinct-PSK two-hop UDP按序完成真实datagram echo；cross-plan/intermediate-target/
      tamper/replay错误、exact nested maximum/+1和invalid-inner no-partial-mutation通过。
- [ ] Success/failure lifecycle、aggregate limits、zero owners、exact TCP/UDP rebind与global/outbound
      secret redaction通过；无unbounded/eager per-hop socket/buffer/task。
- [ ] 一个exact SHA通过Full、Rust 1.85、100+ lifecycle、three native targets、existing TCP/UDP各
      `12/12`+cleanup、schema 3 footprint、blocking reviews及另行授权的manual performance/resource job。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M11-T01 | Compile additive per-outbound credentials and bounded direct/chain plans | — | ready |
| M11-T02 | Compose ordered fixed TCP chains with existing SIP022 flows | M11-T01 | todo |
| M11-T03 | Compose bounded ordered UDP chains with atomic validation/binding | M11-T02 | todo |
| M11-T04 | Prove mixed-credential two-hop TCP/UDP in existing real-process harness | M11-T03 | todo |
| M11-T05 | Qualify one exact integration SHA locally、hosted and with manual performance | M11-T04 | todo |

```text
M11-T01 config/plan contract
  -> M11-T02 TCP vertical slice
  -> M11-T03 UDP vertical slice
  -> M11-T04 real-process security/lifecycle
  -> M11-T05 exact-SHA qualification
```

Tickets drain serially because T02/T03 intentionally share client composition and T04 must exercise the
integrated TCP+UDP plan。Workflow files remain read-only during product tickets。

## Test-footprint forecast

Schema 3 resets at baseline code/tests `16646/27342`、ratio `1.642557`、case/support/fixture
`22795/3950/597`。`TEST-0012` forecasts `640/80/0` new case/support/fixture LOC。This expects milestone
numeric `REVIEW_REQUIRED` (`>600`) while each ticket stays `<=240`；the signal requires Architect/QA
disposition but does not weaken correctness evidence。No fixture、new harness or third equivalent helper
is planned。Known growing-file signals：config/local-support/UDP process files `WARN`，client `run.rs`
`REVIEW_REQUIRED`。

## Blocker / next action

Plan gate is ready：baseline resolves，scope is bounded，dependency DAG is acyclic，overlapping client
ownership is serialized and validation is known。Next action is `mode: execute` for M11-T01 from this
accepted plan commit in its own branch/worktree。No product change、push、workflow dispatch、hosted run、
PR、tag、release or publication is authorized by feature planning。
