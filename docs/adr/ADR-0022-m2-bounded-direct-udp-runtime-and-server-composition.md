# ADR-0022: M2 bounded direct UDP runtime and server composition

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M2；`SPEC-0003`；`TEST-0003`；
  M2-T03、M2-T04、M2-T05；扩展 ADR-0001、ADR-0003、ADR-0005、ADR-0019

## Context and decision boundary

Core/runtime 目前只有 stream contracts、TCP connector/relay/supervisor；server
只 bind TCP。把 UDP socket/session table 放进 Shadowsocks 会让 protocol crate
拥有 runtime policy；把 UDP 塞入现有 stream traits 会破坏已经稳定的 TCP source
contract。

本 ADR 冻结最小 core datagram value、generic runtime ownership、数值资源边界、
same-port TCP+UDP startup、config compatibility、resolution 和 shutdown。

## Outcome invariants

- core 只新增 runtime-neutral bounded datagram value；不泛化或替换现有
  `Session`/`Inbound`/`Outbound`/`Connector` stream traits，不依赖 Tokio。
- runtime 拥有 generic session table、byte permits、fixed queues、direct UDP
  sockets、resolver/deadline、tasks、expiry和 cancellation；不依赖 Shadowsocks。
- 一个 server relay session 恰拥有一个 outbound UDP socket、两方向 depth-4
  queues、byte reservations、protocol adapter state handle、cancellation和一个
  supervisor-owned task。
- application 内所有 session、bytes、datagram和queue都有 fixed numeric bound；
  kernel buffers 保持 OS-bounded，不冒充 application accounting。
- authentication/semantics 先于 resolution/socket/send；reservation 先于 accepted
  replay/session commit。
- `server.listen` 是 TCP+UDP 共用的 address/port；双 bind 是原子 startup
  transaction。
- 每个 task/socket/buffer/session 有一个 owner和 cancel/expiry/shutdown path。

## Frozen numeric profile

| Boundary | Default | Valid range / hard rule |
|---|---:|---|
| UDP sessions | 4,096 | 1..=65,535 |
| global user-space buffered bytes | 16 MiB | 1 MiB..=256 MiB |
| per-session queue | 4 datagrams/direction | fixed，不可配置 |
| complete Shadowsocks wire datagram | — | hard max 65,507 bytes |
| UDP session idle timeout | 300s | 60..=86,400s |
| domain candidates | — | 最多 16 |

Byte budget 按 allocated capacity 计 receive/send scratch、encoded/decoded owned
buffers和 queued datagrams。Ownership move 不重复计费，shared backing/clone 不漏
计；所有失败路径归还 permit。

## Options considered

### Option A：扩展现有 stream traits为统一 transport traits

UDP 是 message-oriented、multi-target、association-based；统一会扩大 core
contract并使 TCP consumers迁移。拒绝。

### Option B：protocol crate拥有 session table和 Tokio sockets

违反 dependency direction，也让 security state同时拥有 process/global
resource policy。拒绝。

### Option C：minimal core value + generic bounded runtime + binary composition

保持 deep-module边界并允许 runtime 以 fake handler 独立验证。接受。

## Decision

### Core and runtime seams

Core 增加等价于 `{ target: TargetAddr, payload: Bytes }` 的 consuming bounded
datagram value；exact public name可在实现中选择，但 payload 超过 caller/runtime
bound时不能构造。

Runtime 对 authenticated/validated datagram 使用 protocol-neutral handler
capability。它负责：

- session admission、generation、oldest eligible expiry和active rejection；
- global allocated-capacity permits和每方向 depth-4 bounded queues；
- one direct socket per server session；
- IP direct send；domain 使用 system resolver，最多16个ordered candidates；
- resolution和 candidate send尝试共用现有 configured connect timeout形成的
  monotonic absolute per-datagram deadline；
- idle timer、target receive、listener failure、graceful shutdown和owner reaping。

Runtime 不解析 SIP022、不记录 wire session ID、不决定 replay acceptance。

### Configuration and startup

Server schema v1 additively接受：

```toml
[udp]
enabled = true
max_sessions = 4096
max_buffered_bytes = 16777216
idle_timeout_ms = 300000
```

Section/fields omitted时使用上述 defaults；`enabled = false` 是 explicit TCP-only
escape hatch。Queue depth和65,507 wire bound不是operator knobs。Client binary
不增加 UDP listener/config；programmatic client protocol API接受同一 validated
limits profile。

`--check-config` 完整验证 ranges但不创建 socket、table、metrics listener或task。
UDP enabled时先完成 TCP和UDP same-address bind，再启动任一 loop；任一 bind失败
释放另一个和所有未启动owner并使startup失败。UDP listener terminal failure为
process-fatal，统一取消/reap TCP与UDP owners。

### Backpressure, failure and shutdown

Capacity full先purge deterministic oldest eligible expired session；没有eligible
项则拒绝new session。Existing session queue/byte full只drop/fail affected datagram，
不破坏其他session或推进accepted replay/activity。

Graceful shutdown同时停止TCP accept和UDP receive；已admitted work最多drain到既有
`runtime.shutdown_grace_ms`，随后取消并reap全部tasks/sockets/buffers/sessions。
Target send/receive、resolve、idle或counter failure只终止affected session。

### Observability

新增稳定低基数families：

- `ferrum2_udp_sessions_active{role}`；
- `ferrum2_udp_datagrams{role,direction,outcome}`；
- `ferrum2_udp_failures{role,stage,reason}`；
- `ferrum2_udp_bytes{role,direction}`；
- `ferrum2_udp_buffered_bytes{role}`；
- `ferrum2_udp_replay_rejections{role,direction,reason}`；
- `ferrum2_udp_forced_shutdown{role}`。

Labels均为closed enums。Method、PSK、key、nonce、wire session/packet ID、target、
source/peer address不得成为label或trace field。Trace correlation只能使用独立的
process-local bounded ID。

## Consequences and tradeoffs

- Positive：protocol security state与runtime resource ownership可独立测试和
  review。
- Positive：fixed queues + byte permits避免input-dependent allocation。
- Negative：one socket/task per relay session消耗更多OS resources；4,096 default
  和 fail-closed admission使代价可预测。
- Negative：旧M1 config默认会开始bind UDP；若该UDP port被占用，upgrade startup
  可从success变failure。`[udp].enabled=false` 可保留TCP-only run behavior。

## Compatibility, migration and rollback

TCP bytes、listener semantics、metric families和source contracts不变。Schema仍为
v1；M1 binary因 deny-unknown-fields无法读取含 `[udp]` 的新config，rollback前需
删除该section。没有 persisted sessions或migration。

## Verification seam

- core/architecture direct contract和dependency policy；
- generic runtime reservation/rollback/saturation/expiry/concurrency table；
- allocated-capacity accounting和depth-4 backpressure；
- resolver 16-candidate/single-deadline paused-time rows；
- config defaults/ranges、offline zero-resource和UDP-disabled rows；
- partial bind rollback、same-port local echo、restart/rebind、shutdown owner
  snapshots；
- metric series identity和secret/session/target sentinels。

## References

- `docs/research/M2-udp-baseline.md`
- `docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md`
- `docs/adr/ADR-0003-m0-configuration-and-cli-contract.md`
- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/adr/ADR-0019-m1-tcp-target-address-and-resolution-boundary.md`
