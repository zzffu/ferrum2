# ADR-0012: M0 phase deadlines and partial relay accounting

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；M0-T03、M0-T06、M0-T07；
  部分取代 ADR-0010 的 fused client open 与“prefix 后使用 unchanged relay result”
  假设，以及 ADR-0005 的 relay failure accounting contract；本ADR的manifest/
  dependency non-goal被ADR-0013两个test-only binary dev edges部分取代；
  ADR-0016只放宽private test helper/result-carrier spelling，不改变separate
  deadline、partial accounting、payload ordering或production interface semantics

## Context and problem

T07 composition 发现两个既有 M0 行为无法由当前 upstream seam 实现：

- `ClientTcpOutbound::open_stream` 把 configured-server connection 与 SIP022 request
  contiguous first-write 合并。binary 因而不能分别应用 configured
  `connect_timeout`（默认 10 秒）与连接成功后新开始的 configured
  `handshake_timeout`（默认 5 秒）。
- `relay_lifecycle` 只在 success 返回 `RelayStats`；I/O、idle timeout 或
  cancellation 会丢失失败前已经成功交给 application-facing writer 的 byte counts，
  与既有 observability contract 冲突。

binary phase notification、timeout heuristic 或 write-counting transport wrapper 会
引入 temporal coupling、错误分类或重复 runtime relay semantics。问题必须在拥有
对应 state/accounting 的 deep module 内做最窄修复。

## Decision drivers and invariants

- config schema、validated duration与默认值不变；实现必须使用每个validated config的
  configured values，不能把默认10秒/5秒硬编码进binary。
- protocol crate保持executor-neutral，唯一unsplit transport owner不能暴露或复制。
- SOCKS success只能发生在request contiguous first-write完整成功后。
- forwarded-byte count只来自successful nonzero application writes，并在所有terminal
  outcomes保留方向。
- one owner task、two local futures、two fixed buffers、no-channel topology不变。

## Options considered

### Option A：opaque phase capability + runtime-owned partial accounting

选择。state owner提供最窄capability/result seam，binary只应用configured deadlines
并映射已有observability reason。

### Option B：binary notification/timeout heuristic/writer wrappers

拒绝。它引入temporal coupling、可能把timeout误分为Detection，并在两个binaries
重复relay accounting。

### Option C：公开raw transport/state或由protocol拥有relay

拒绝。前者破坏unsplit deep-module ownership；后者复制runtime的idle、cancellation、
backpressure和half-close policy。

## Decision

### Opaque client connect capability

`ferrum2-shadowsocks` 将 client open 分为两个 consuming phases；精确 Rust 名称/
lifetime spelling 可为 borrow checker 作机械调整，但 capability 与 error contract
不得改变：

```text
ClientTcpOutbound::connect_server()
  -- configured connect_timeout (default 10s) -->
ConnectedClientOpen
  -- consuming write_request(application_target),
     fresh configured handshake_timeout (default 5s) -->
ClientFlow
```

- `ClientTcpOutbound` 继续只持有 validated configured Shadowsocks server endpoint；
  connector 只收到该 endpoint。application target 只在第二阶段编码进 request。
- `ConnectedClientOpen` 是 opaque、single-use capability，保留唯一 unsplit
  transport 与建立 request flow 所需的 private capabilities；不暴露 raw transport、
  cipher、salt、nonce、scratch、phase transition 或 extraction/reunite method。
- salt/time/padding generation、fixed scratch creation、request encoding与contiguous
  first-write全部在consuming `write_request` future内，因此都受fresh configured
  handshake budget；`connect_server`不得提前执行这些handshake steps。
- protocol seam 仍 executor-neutral，不引入 Tokio。binary 只在 future 外包裹
  Tokio deadlines，不创建 detached task。
- configured connect budget 在 connect success 时结束；configured handshake
  budget从第二phase重新计时。默认值分别为10秒/5秒；慢但合法的connect不消耗
  handshake budget。
- connect deadline 映射为 `ConnectErrorKind::Timeout`，在 SOCKS success 前发送
  general failure。request first-write deadline是binary-owned phase timeout，记录
  `Reason::HandshakeTimeout`，正常 drop sole transport owner，abortive count 为 0；
  它不扩展或伪造`ShadowsocksError`。
- 实际 first-write short/I/O/auth semantic failure仍遵循 ADR-0010 的 Detection
  table。SOCKS success只在完整 request first-write 成功后发送。
- 为 core `Outbound` compatibility 保留的 fused convenience `open` 可以内部顺序
  调用两个 phases；T07 composition 必须使用 phased interface。

### Relay failures retain partial statistics

`ferrum2-runtime` 的 relay outcome 同时携带 terminal kind 与已完成统计：

```rust
Result<RelayStats, RelayFailure { kind, stats }>
```

精确 enum/type spelling 可在 T06 实现内调整，但以下语义固定：

- success 与 I/O failure、idle timeout、cancellation 都返回截至 terminal 时的
  direction-separated counts；
- 只在 application-facing `AsyncWrite` 返回成功且 `n > 0` 的既有 observation
  point 增加 count；不计 read-ahead、ciphertext、protocol overhead、pending、
  write-zero 或未接受 bytes；
- partial-write 后的 error/timeout/cancel 保留已成功 prefix，不 double count；
- 原 one owner task、two local futures、two 16 KiB buffers、no data channel、
  backpressure、half-close、cancellation 和 shutdown topology不变。

### Server initial-payload prefix

T07 server connection owner 在 direct connect 后、ordinary relay 前运行
binary-private bounded prefix loop：

- `Session.initial_payload` 原 byte sequence完整、恰好一次写入 target；
- 每次 successful nonzero target write 重置 idle deadline；`Pending` 不重置；
- cancellation、idle timeout、write-zero 或 write error立即终止，返回精确已写
  prefix count，并且绝不 poll `ServerFlow` 或开始 ordinary relay；
- empty prefix零 write，直接进入 relay；
- prefix success后只把尚未计入的 prefix bytes与 runtime relay outcome stats相加；
  方向分离、normal/failure均不 double count。

该 loop 不公开为 protocol/runtime API，不增加 buffer、clone、queue、task、channel 或
per-flow mutex。

## Error and observability mapping

| Phase/outcome | Closed result / metric boundary |
|---|---|
| configured-server connect deadline | `ConnectErrorKind::Timeout` → `ConnectTimeout`，pre-success SOCKS failure |
| request first-write deadline | binary `Reason::HandshakeTimeout`，normal drop，abortive 0；无新protocol error |
| actual first-write failure | ADR-0010 exact Detection classification |
| relay I/O/idle/cancel after partial progress | existing terminal reason plus retained partial `RelayStats` |
| initial-payload prefix partial failure | existing relay/timeout/cancel reason plus exact successful prefix bytes |

“Forwarded bytes”仍表示本进程 application writer 已接受的 bytes，不声称 remote
application 已消费。metric names、labels、cardinality、stage/outcome vocabulary
不变。

## Non-goals

- 不改变 SIP022 bytes、crypto、replay、detection、binding、target、method 或
  protocol error taxonomy。
- 不修改 `ferrum2-core` traits/`Session`、config field/default/range；除
  ADR-0013精确批准的两个binary Tokio `test-util` dev edges外，不修改manifest/
  `Cargo.lock`/dependency。
- 不在 `ferrum2-shadowsocks` 引入 Tokio，不新增 public observer/callback/test hook、
  management API、metric 或 raw protocol state。
- 不 split transport/direction tasks，不引入 channel、per-flow mutex、protocol-owned
  relay 或 runtime 对 protocol fatal token 的知识。
- 不改变产品范围、API-visible operator behavior、reference pins、platform matrix 或
  remote authorization。

## Consequences and tradeoffs

### Positive

- 现有config durations第一次能精确覆盖各自phase，慢connect不会侵占handshake。
- timeout、I/O、idle与cancel都保留既有reason和failure前application byte evidence。
- ownership与task/buffer topology不变，T03/T06可在disjoint worktrees并行。

### Negative

- protocol增加一个workspace-public但fields-private的typestate capability。
- runtime controlled relay result需要调用者同时处理failure kind与stats。
- T07 prefix loop必须显式处理partial write、progress deadline和count合并。

## Compatibility and upstream divergence

SIP022 revision/wire、KDF/nonce、replay/binding/detection、core contracts、config schema/
defaults/ranges、metrics schema、reference pins与platform matrix均不变。内部Rust seam
只服务publish=false workspace composition，不增加operator/public network API。
sing-box/shadowsocks-rust行为不用于决定deadline或accounting semantics。

## Migration and rollback

无 wire/persisted-state migration。T03 与 T06 窄修复可在 ownership-disjoint
worktrees并行；两者都通过 ticket/integration Architect 与 QA gate 后 T07 才能恢复。
回滚时同时从 integration 排除对应 repair commits，并保留 T07 partial checkpoint；
不得在 binary 用 shim 恢复旧 fused/error-only interface。

## Verification plan

- T03 controlled-future tests只证明connect-complete与request-first-write可独立
  Pending/complete、capability被一次消费、cancel/drop释放sole transport owner且不
  创建task；T03不得依赖Tokio time。
- T06 tests覆盖 normal、bidirectional partial success、partial-write-then-error、
  idle timeout、cancellation、write-zero 与 half-close，并逐方向断言 partial stats。
- T07 paused-time adapter/composition tests使用non-default durations和default
  10秒/5秒各一组，证明configured connect budget与fresh configured handshake budget
  独立、慢connect不消耗后者、SOCKS reply timing、timeout/cancel sole-owner drop与
  零detached task；同时覆盖prefix partial progress、progress-reset idle、
  cancel/error/empty prefix、no-relay ordering和最终direction-separated metrics。
- ADR-0013 policy与feature-tree evidence必须证明`test-util`只由两个binary
  dev-kind edges启用，排除dev edges的production graph不含该feature且lock无新增hunk。
- T03/T06 原 ticket commands、workspace quick/full、strict Clippy、formatting 与
  fixed-baseline diff仍须全部通过。

## References

- `ADR-0003`：validated runtime timeout fields、ranges与10秒/5秒defaults。
- `ADR-0005`：runtime ownership、idle/cancellation、half-close与observability。
- `ADR-0010`：opaque unsplit SIP022 flow与exact terminal classification。
- `SPEC-0001`、`TEST-0001`、M0-T03/M0-T06/M0-T07。
