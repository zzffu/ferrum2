# ADR-0027 — M7 tagged static composition

- **Status:** Accepted
- **Date:** 2026-08-03
- **Related:** `SPEC-0008`、`TEST-0008`、M7-T01～T04；extends ADR-0023/0024

## Context

当前两个 binary 都把一份合法 schema v1 配置归一化成一个 listen、一个固定
outbound 和一个 `ProcessSupervisor` transaction。`ferrum2-config` 已保证完整
semantic validation 先于 runtime side effect；`ProcessSupervisor` 已接收任意
`Vec<ProcessRoot>`，在全部 root prepare 后才 activate，并在失败时逆 ownership
顺序 rollback。M7 只需要让多个既有 concrete adapter 进入这两个现有 module
interface，不需要新的 protocol 或 lifecycle seam。

M7 不加入 dynamic routing。每个 inbound 在配置中静态引用一个 outbound；一个
flow/datagram 一旦从该 inbound 进入，就只使用该引用。未来 routing、Tailscale
Endpoint 或新 adapter kind 需要独立 contract。

## Decision

### Additive schema v1 shape and legacy normalization

两个 role-specific parser additive 接受 root-level `[[inbounds]]` 与
`[[outbounds]]`。Tagged document 不得同时出现 legacy `[client]` 或 `[server]`；
legacy document 不得出现 tagged arrays。Mixing、空集合或只出现一侧均为
`config.semantic`。

Client tagged shape：

```toml
schema_version = 1

[[inbounds]]
tag = "socks-a"
listen = "127.0.0.1:1080"
outbound = "ss-a"

[[inbounds]]
tag = "socks-b"
listen = "127.0.0.1:1081"
outbound = "ss-b"

[[outbounds]]
tag = "ss-a"
server = "127.0.0.1:8388"

[[outbounds]]
tag = "ss-b"
server = "127.0.0.1:8389"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
```

Server tagged shape：

```toml
schema_version = 1

[[inbounds]]
tag = "ss-a"
listen = "127.0.0.1:8388"
outbound = "direct-a"

[[inbounds]]
tag = "ss-b"
listen = "127.0.0.1:8389"
outbound = "direct-b"

[[outbounds]]
tag = "direct-a"

[[outbounds]]
tag = "direct-b"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
```

Client inbound 仍只表示 SOCKS5；client outbound 仍只表示一个 Shadowsocks server；
server inbound 仍只表示 Shadowsocks；server outbound 仍只表示 direct。不存在
`type`/factory/registry 字段，因为当前 binary role 已经确定 concrete adapter。
未来新增 kind 可用 optional additive field 或 successor schema 决定，不在 M7
提前创建 selector。

Legacy `[client].listen/server` 和 `[server].listen` 在 validated config module 内
归一化成各一个 synthetic inbound/outbound。Synthetic tag 不进入 operator output；
现有 method/PSK、runtime、replay、UDP、logging、metrics defaults、ranges 和副作用
选择保持 byte-for-byte fixture/effective-value compatibility。

### Tags and references

- 每份 tagged document 的 inbound/outbound tag 共用一个 namespace，必须全局唯一；
  comparison 是 case-sensitive exact bytes。
- Tag 是 `1..=64` ASCII bytes，只接受 alphanumeric、`.`、`_`、`-`；tag 值不进入
  error、trace 或 metric label。
- 每侧接受 `1..=64` entries。每个 inbound 的 `outbound` 必须在 outbound set 中
  exact resolve；每个 outbound 至少被一个 inbound 引用。
- 每个 role 的 inbound listen 必须唯一；metrics listen 必须与全部 inbound listens
  不同。Client 任一 outbound server 不得等于任一 local inbound listen，避免用
  tagged config 隐式组成 local chaining/cycle。
- Duplicate、missing、dangling、wrong-namespace、unreferenced 或 invalid tag/reference
  在 `load_client`/`load_server` 返回前以 closed、redacted `config.semantic` 拒绝。

Tagged graph新增的non-value field identities固定为`inbounds`、`outbounds`、
`inbounds.tag`、`inbounds.listen`、`inbounds.outbound`、`outbounds.tag`和
`outbounds.server`。Collection/count/mixing使用对应collection field；tag collision
使用第二个冲突entry所属tag field；reference/unreferenced使用
`inbounds.outbound`/`outbounds.tag`；endpoint conflict使用对应listen/server field。
这些field不含index或operator value。

Validated config 可以保留 tag 或把已解析引用变成 typed index；这是 config module
implementation freedom。Binary 不得重新解析 operator strings，也不得在启动后以
`expect` 代替 preflight validation。

### Shared policy and static behavior

M7 保留一个 process-wide `[shadowsocks]` method/PSK、一份 `[runtime]`、server
`[replay]`、一份 `[udp]`、`[logging]` 和 optional `[metrics]`。因此 M7 支持多个
listen/upstream identities，但不增加 per-entry PSK/method、SIP023 或 multi-user。

- `runtime.max_connections` 是所有 TCP inbounds 共享的 aggregate admission cap；
  `listen_backlog` 作用于每个 listener，其余 deadlines/process grace 继续全局。
- Server TCP replay state 对全部 inbounds 共享。Client UDP session-ID collision set、
  client/server UDP session count 和 allocated-byte budget 都是 process-wide。
- Server UDP session 绑定首次 accepted local inbound；同 session 从另一 local
  inbound 到达时必须在 replay/activity/peer/queue/target mutation 前拒绝。Response
  从该 session 的 bound inbound socket 发出；同一 inbound 内既有 validated peer
  roaming 语义不变。
- Tag 只选择 concrete adapter；没有 fallback、round robin、health check、load
  balancing、route rule、chaining 或 outbound preconnect。

### Atomic process composition

每个 binary 复用现有 `ProcessRoot`/`ProcessSupervisor` seam。全部 configured TCP
listeners、server UDP listeners、optional metrics listener 以及会阻止 activation 的
protocol/runtime owners 必须在一个 transaction 中 prepare；任何 first/middle/last
prepare 或 activation failure 都 rollback 已取得资源，且没有 root 开始 public
polling。Active 后任一 required listener/root terminal outcome 仍取消并 reap 全进程。

Outbound adapter 在 flow/datagram 被接受后按静态引用使用；M7 不为无 startup I/O
的 outbound 伪造 root。若多个 listener 需要共享 admission/session capacity，runtime
可增加 concrete cloneable owner value，但不增加 trait。

## Rejected options

### Endpoint interface or generic service graph

当前只有 binary-fixed concrete adapter；一个 hypothetical interface 没有第二个真实
adapter，只增加 caller knowledge 和测试 surface。拒绝。Tailscale Endpoint、TUN、
transparent inbound 或 routing 出现时再以实际需求决定 seam。

### One independent supervisor or resource budget per inbound

它会使 partial activation 跨 supervisor 无法统一 rollback，并把现有 process-wide
connection/UDP limits 乘以 inbound count。拒绝。

### Schema v2 or reinterpret legacy tables

本功能可由 optional additive shape表达；改变既有 document 的 defaults/meaning没有
必要。拒绝。

## Consequences

- Positive：tag/reference graph 在零 side effect 的 config module 一次验证，binary
  只组合已解析 concrete contexts。
- Positive：现有 deep lifecycle interface直接覆盖任意 root count；atomic startup、
  shutdown 和 owner evidence 不复制。
- Negative：M7 没有 dynamic routing；改变绑定需要编辑配置并重启。
- Negative：single method/PSK 和 global budgets限制每进程隔离；per-entry credentials
  或独立 quotas 需要后续明确需求和安全 contract。

## Compatibility and rollback

M3 preserved v1 cohort继续不经修改地接受并保持 effective behavior。新 binary 接受
tagged documents；旧 binary按ADR-0023允许的compatibility direction拒绝未知arrays。
Rollback删除 tagged parser/composition path即可恢复 legacy-only product；不得保留只
解析不执行的 inert tagged config。Wire、protocol state machines、CLI、run codes、
trace keys和metric family identity不变。

## Verification seam

- Config interface table证明legacy normalization、tag/reference/count/endpoint negatives、
  redaction和zero-resource check。
- Concrete client/server adapter tests证明static mapping、shared budgets/replay、server
  UDP inbound binding和无fallback。
- Failure-position process table证明all-root prepare-before-poll、reverse rollback、fatal
  cancellation、shutdown/rebind和owner baseline。
- Existing TCP/UDP local/external matrices、MSRV、三native targets、Full和test budget在
  一个accepted exact SHA上回归。
