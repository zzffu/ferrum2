# M10 — 手动 outbound selector 核心

- **Status:** validating
- **Baseline:** `99bd62e9673f8743a0ea6597962fbfc22b3e3ce7`
- **Strategy:** drain
- **Owner:** primary thread

## Outcome

在现有 tagged outbound namespace 与 `RouteTable` seam 上增加有界、可嵌套且无环的手动
selector。Static inbound binding、route rule 与 `route.final` 可指向 selector；公开 Rust
interface 可查询和原子切换其当前直接成员。每次既有 outbound-selection call 取得 concrete
identity 后保持该 snapshot，之后的选择才观察新成员；legacy/M7/M8 行为、SIP022 安全、资源
ownership 与 process lifecycle 不变。

## Baseline evidence

- Core：`ferrum2_core::route::RouteTable` 在 `crates/ferrum2-core/src/lib.rs:168-280`
  已集中 static/routed selection，但 action 仍是 concrete `usize`，没有可变 selector state。
- Config：`validate_client_graph` / `validate_server_graph` 最终都进入
  `validate_route`（`crates/ferrum2-config/src/lib.rs:401-690`）；现有 raw outbounds 是两个
  role-specific concrete shape（`:983-1010`），全部 action 在 load 返回前解析为 concrete ID。
- Client：TCP 在 SOCKS target 后选择一次（`bins/ferrum2-client/src/run.rs:537-557`）；static
  UDP 在 association setup 选择一次（`:691-725`），routed UDP 每个 validated datagram 选择
  一次（`:897-935`）。
- Server：TCP 在 authenticated request 后选择一次（`bins/ferrum2-server/src/run.rs:1262-1285`）；
  UDP 每个 authenticated pending request 在 reserve/commit 前选择（`:803-920`）。
- Public config seam：`ferrum2_config::{load_client,load_server}`（`:294-305`）已是 zero-resource
  integration-test surface；workspace 不需要新 crate、dependency 或 runtime。

## Assumptions fixed by ADR-0029

- Additive schema v1 使用独立 tagged-only `[[selectors]]`，不把现有两种 concrete
  `[[outbounds]]` 改成 polymorphic type。Selector tag 与 inbound/outbound tag 共用现有全局
  case-sensitive namespace。
- 每个 selector 明确给出 `1..=64` 个 unique `outbounds` member tags 与一个必须存在的
  direct `default` member。Member 可以是 concrete outbound 或另一个 selector；完整 graph
  必须有界、引用完整、从 binding/route roots 可达且无 self/indirect cycle。
- 一个 runtime-neutral core module 持有 immutable graph 与 per-selector atomic current slot。
  Public control interface只有 `selected(selector)` 与 `switch(selector, member)`；clone handles
  共享同一 process-local state，invalid operation不修改状态且错误不回显 tag。
- `RouteTable::select` 继续只向 binaries 返回 concrete outbound index，并在内部解析当前
  selector chain。因此现有 TCP/UDP call sites及其选择粒度保持；已经返回的 concrete identity、
  socket、UDP leg 或 in-flight response不被后续 switch 改写。
- Client 与 server 都接受 selector refs；server 当前成员仍全是 concrete direct identities，
  不借此加入第二种 adapter。Restart重新使用 configured default，不持久化 current state。

## Non-goals

- HTTP、IPC、CLI、Clash API、management endpoint、watcher、persistence、hot reload或远程控制。
- 自动选择、URL test、retry、fallback/failover、health check、load balancing、chaining或
  connection interruption。
- CAS/version/revision、multi-selector transaction、dynamic member mutation或runtime graph rebuild。
- 新 outbound/inbound kind、`Endpoint`/factory/registry trait、per-entry credential/quota、DNS/Geo/
  user policy、SIP023/multi-user、transparent/TUN或Tailscale Endpoint。
- 新 dependency/provider/workflow job、performance threshold、package、release或publication。

## Exit criteria

- [x] Legacy、M7 static与M8 routed schema v1 cohort保持；selector count/tag/member/default/
      reachability/cycle negatives在任何 runtime side effect前以closed redacted errors失败。
- [x] Public Rust interface通过integration test证明default/current query、valid switch、nested
      resolution、unknown selector/member no-mutation与bounded concurrent readers/writers。
- [x] Static inbound binding、route rule与`route.final`均可指向selector；每个selection call只得到
      一个concrete outbound，selected failure不切换、不重试、不尝试 sibling。
- [x] Client/server TCP和UDP沿现有auth/bounds/mutation ordering使用最新尚未snapshot的选择；已经
      snapshot的flow/datagram/leg/response不受switch影响。
- [x] 现有aggregate admission/replay/UDP session/bytes/IDs、source/inbound binding、shutdown/rebind、
      trace与metric identities保持，selector/tag不进入telemetry。
- [ ] 一个exact SHA通过Full、Rust 1.85、100+ lifecycle、three native targets、现有TCP/UDP各
      `12/12`+cleanup、schema 3 footprint与blocking review；缺失/失败/未授权不算通过。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M10-T01 | Add the bounded selector graph, additive config, and public atomic control interface | — | done |
| M10-T02 | Prove all existing client/server TCP/UDP selection points consume selector snapshots | M10-T01 | done |
| M10-T03 | Reuse process/platform/interop evidence and qualify one exact integration SHA | M10-T02 | blocked |

```text
M10-T01 core/config/control contract
  -> M10-T02 existing four data-plane selection seams
  -> M10-T03 exact-SHA qualification
```

Tickets serialize because T02 reviews the exact T01 graph/interface and owns both large binary test
modules；T03 keeps product paths read-only and runs/reuses process evidence only after T02 integrates。

## Test-footprint forecast

Schema 3 starts from code/tests `15996/26916` at the exact baseline，ratio `1.682671`。The cheapest
sufficient evidence forecasts `230/0/0` new case/support/fixture LOC：T01 `155/0/0`，T02
`75/0/0`，T03 `0/0/0`。No new helper、fixture or process harness is planned。

Growing `config_contract.rs` is expected to report file `WARN` from its current `871` semantic test
LOC；growing client/server `run.rs` is expected to report file `REVIEW_REQUIRED` from current
`3390/1777` test LOC。These are explicit Architect/QA maintenance decisions，not correctness waivers；
splitting private binary composition into a duplicate harness is rejected。

## Validation evidence / blocker

M10-T01 integrated product exact `e6ede87ae314fe201bc6412bacd360bc0505cf4c`。M10-T02 integrated
product exact `93ed9d91929200a1786694ffd59e491b7188a5d1` after Architect/QA both
`PASS_WITH_NOTES` and no blocking finding；four focused tests、packages `47/47`、Clippy/fmt/diff、
integration Full、lifecycle `1/1` in `126.02s` and docs passed。Milestone footprint is
`403/0/0` case/support/fixture with integrity/change `PASS`；both large `run.rs` file
`REVIEW_REQUIRED` signals are explicitly accepted by `ARCH-M10T02-001` and `M10-T02-QA-N01`。
M10-T03 locally validated product ancestor `93ed9d91929200a1786694ffd59e491b7188a5d1`
(not yet qualified) at checkpoint `eb56b81b709a8e18e4560fbad8cd3b3b27ced44a`。Public selector
`2/2`、four data-plane
tests `1/1` each、real-process TCP/UDP `1/1` each、architecture `9/9`、Rust 1.85 and serial Full
passed；workspace was `308 passed / 5 ignored` and lifecycle `1/1` in `126.57s`。Footprint remains
code/tests `16646/27319`、ratio `1.641175`、cumulative `403/0/0` with integrity/change `PASS`；the
zero-exit milestone `REVIEW_REQUIRED` is accepted by `ARCH-M10T02-001` and `M10-T02-QA-N01`。
Exact-product Architect inspection bound target `93ed9d91929200a1786694ffd59e491b7188a5d1`、tree
`ded9f1e59da892250215f13a271b927579192592` and parent
`c55c6c8e737e419b5fa036bf5572183b90f56cd0`；verdict was `PASS_WITH_NOTES` with no new
blocker、major or minor，and it is local architecture evidence only。
Reviewed T03 repair `a274a7cdb71ad74af5b2b8bb36cd2f32d2b96396` received targeted Architect
and QA `PASS`；`ARCH-M10T03-001` and `M10-T03-QA-001/002/003` are resolved。Current local
integration descends from that repair，and post-fast-forward diff-check plus ticket/milestone footprints
passed。

M10 is `validating` and M10-T03 is `blocked`：one accepted exact SHA/run/attempt must complete
`quality`、`test-footprint`、`msrv`、`platform / windows-msvc`、`platform / linux-gnu`、
`platform / linux-musl`、`interop` (TCP/UDP `12/12` plus cleanup)、`performance` and
`qualification`。Performance is required only as current-workflow regression/aggregate-dependency
evidence；M10 adds no performance threshold or claim。This requires separate explicit authorization
for one non-force push；only the final exact hosted-SHA review remains pending。No push、hosted run、
rerun、dispatch、PR、tag、release or publication was performed；old M8 evidence is not M10 PASS。
