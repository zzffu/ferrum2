# M7 — 具名多 inbound/outbound 静态组合

- **Status:** executing
- **Baseline:** `302fd777f4da62a8c1d4d52d81502056f02089c8`
- **Strategy:** drain
- **Owner:** primary thread

## Outcome

在两个现有 binary 中支持多个有界、具名的 concrete inbound/outbound；每个 inbound
在启动前静态解析一个唯一 outbound tag。Legacy 单实例 schema v1 配置保持原行为；
全部 listener/protocol roots 复用一个 `ProcessSupervisor` transaction，任一 prepare
失败原子 rollback，不创建 `Endpoint` interface。

## Baseline evidence

- Config：`ferrum2-config::{load_client,load_server}` 当前各返回单 listen/upstream，
  `Validated*Config` 保存一份全局 method/PSK/runtime/UDP policy。
- Client：`run_with_registry_and_metrics` 当前组合一个 SOCKS5 TCP root；UDP association
  是该 root 的 bounded child。
- Server：`run_with_registry` 当前组合一个 Shadowsocks TCP root、optional same-address
  UDP root和optional metrics root。
- Lifecycle：`ProcessSupervisor::run_until` 已对任意 root vector实现prepare-all、
  activate-all、reverse rollback、fatal arbitration和bounded reap；M7不复制该policy。

## Assumptions fixed by ADR-0027

- Tagged shape是additive schema v1；legacy与tagged shape不能混用。
- Tag在inbound/outbound间全局唯一、大小/字符/count有界；所有outbound必须被引用。
- 仍是一份process-wide method/PSK、runtime/replay/UDP policy；不加入per-entry key。
- Binding是static inbound→outbound；没有routing、fallback、load balancing或chaining。
- Existing config/process interfaces是测试seam；binary使用concrete adapters，不新增
  `Endpoint` trait、factory、registry或dependency。

## Non-goals

- TCP/UDP dynamic routing、DNS、multi-upstream group、health check、load balancing、
  fallback或proxy chaining。
- Per-entry method/PSK、SIP023、多用户、new inbound/outbound kind或shared public UDP
  listener。
- Tailscale Endpoint、transparent/TUN、hot reload、management API或tag metric label。
- Performance threshold、package、release、publication或任何未单独授权的remote action。

## Exit criteria

- [ ] Legacy client/server v1 cohort继续原样接受；tagged/legacy normalization和所有
      tag/reference/count/collision negatives在zero-resource check中fail closed且脱敏。
- [ ] 两个binary支持至少两个inbounds/outbounds、shared outbound和无fallback的static
      mapping；global method/PSK及wire不变。
- [ ] TCP admissions、TCP replay、UDP IDs/sessions/bytes/replay在全部inbounds间保持
      aggregate ownership；server UDP session绑定local inbound并从同一inbound回复。
- [ ] First/middle/last TCP/UDP/metrics prepare或activation失败不poll service，逆序
      rollback全部资源；root fatal、signal、forced和restart/rebind回baseline。
- [ ] Existing legacy TCP/UDP/local lifecycle回归和bounded tagged real-process matrix通过；
      tags不进入existing trace/metric identity。
- [ ] One exact SHA passes Full、Rust 1.85、three native targets、TCP/UDP各`12/12`+
      cleanup、test budget和blocking review；missing/failed evidence blocks close。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M7-T01 | Normalize legacy/tagged config and reject every invalid graph before side effects | — | done |
| M7-T02 | Compose server multi-listener TCP/UDP/direct roots with shared state and atomic rollback | M7-T01 | done |
| M7-T03 | Compose client multi-listener SOCKS/Shadowsocks roots with shared bounds and static mapping | M7-T02 | done |
| M7-T04 | Prove multi-instance real-process behavior and qualify one exact SHA | M7-T03 | active |

```text
M7-T01 config graph
  -> M7-T02 highest-risk server TCP/UDP transaction
  -> M7-T03 client static composition
  -> M7-T04 exact-SHA qualification
```

Tickets serialize because T02 establishes the concrete shared admission/runtime owner consumed by
T03，and T04 intentionally reuses product-owned harness paths only after both binary changes
integrate。No concurrent writer owns overlapping product paths。

## Blocker / next action

No local execution blocker。M7-T03 is integrated and reviewed at exact
`b3f7ff8e6dad22d37f8fb95bc42c7e83c6834c72`；M7-T04 is the only active frontier。T03/T04 budget
failures remain recorded but nonblocking under the explicit user waiver；the milestone exit record
must not claim a budget PASS。Remote push/run、PR、tag、release and publication remain unauthorized。
