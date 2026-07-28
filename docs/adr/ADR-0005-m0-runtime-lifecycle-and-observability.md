# ADR-0005: M0 runtime lifecycle、背压与可观测性

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T04、M0-T06、M0-T07；关闭 DEC-006；ADR-0016仅将private registry/counter evidence realization定义为selected profile，不改变lifecycle topology、bounds、accounting、half-close或shutdown outcome

## Context and problem

M0 的 TCP path 同时涉及 listener、handshake、direct connect、两个 relay direction、
metrics endpoint 和 shutdown。若每个方向自由 spawn、用 data channel 隔离或依靠
“最终会 drop”，就无法证明 task/socket/buffer 有 owner 和 termination path。
tracing/Prometheus 若接受自由字符串，secret、destination 和 label cardinality
也无法审核。

## Decision drivers and invariants

- Tokio worker thread 不得执行阻塞操作。
- accept、handshake、connect、idle、shutdown 和 metrics HTTP 都有数值 limit。
- 所有 channel/queue 有界；M0 data plane 不需要 channel。
- TCP half-close 保留反方向 drain；fatal error 只终止受影响 flow。
- listener failure 和 process shutdown 必须回收 owned tasks/sockets/buffers。
- metric labels 是 closed enums；secret 与 destination 不进入 trace 或 labels。

## Options considered

### Option A：root supervisor + 每连接一个 owner task + task-local relay futures

root 拥有 listeners 和 connection `JoinSet`；一个 flow task 同时拥有 socket halves、
buffers、permit 和两个 relay futures。backpressure 直接由 writer 传播到 reader。

### Option B：每个 relay direction 一个 spawned actor 和 bounded mpsc

背压显式，但每连接增加 task/channel/cancellation states，response-header ordering、
half-close 和 leak proof 更复杂。

### Option C：detached tasks + process exit 回收

不能验收 graceful shutdown、listener failure 或 repeated lifecycle，无 owner contract。

## Decision

### Supervisor 与 connection ownership

- 每个 binary 在 config 完整验证后创建一个 top-level supervisor。
- proxy listener、可选 metrics listener、signal source 和 connection `JoinSet` 均由
  supervisor 拥有；不得 detached spawn。
- proxy accept loop 在调用 `accept` 前先取得 `Semaphore(max_connections)` permit。
  permit 与 accepted socket一起移交唯一 connection owner task，task 结束时释放。
  这使 active sockets/tasks 不超过 validated cap；kernel listen backlog 为
  `listen_backlog`。
- listener accept 的非瞬态失败是 process-fatal：停止全部 accept、触发 cancellation、
  按同一 shutdown contract 回收现有 flow，run mode exit 1。
- 一个 connection owner task拥有 inbound/outbound streams、protocol state、
  direct connector、buffers、permit 和 test registry token。两个方向是同一 task
  内并发 futures，不另 spawn，不使用 data-plane channel。

### Relay、背压与 half-close

- 每方向 application buffer 使用 M0 固定常量 `RELAY_BUFFER_BYTES = 16384`，不是
  operator config field。
  subsequent protocol data-frame output 至多
  `18-byte encrypted length chunk + (16384 + 16)-byte encrypted payload = 16418`
  bytes；包含response salt/fixed header的first-response contiguous output至多
  `16 + 43 + 16384 + 16 = 16459` bytes。decrypt side另有最多`65535 + 16 =
  65551` bytes的单一reusable wire scratch。每flow的buffer数量固定，不由
  packet/frame数量增长。
- relay 只有在当前 writer 已接受/flush 先前 bytes 后才继续对应 reader；stalled
  target 必须最终停止从 peer 读取。没有 prefetch queue。
- 某方向读取 EOF 时，对另一 stream 的 write half 调用 shutdown，然后继续运行
  反方向直至 EOF。正常 half-close 不取消反方向。
- authentication、protocol、connect 或非 EOF relay I/O fatal error 取消该 flow 的
  两个 direction，关闭其 sockets，等待 task内 futures drop；不影响其他 flow。
- authenticated request initial payload 由 connection owner 在 direct connect
  成功后先写 target，再开始普通 relay；response first payload 必须经过 ADR-0004
  header path。
- runtime socket adapter实现core `AbortiveClose::mark_abortive(&mut self)`；这是
  唯一设置`SO_LINGER=0`的入口。它不依赖`ferrum2-shadowsocks`，普通drop/EOF/
  shutdown走normal close。mark后transport只能由owner立即drop；T03 typed terminal
  state和T06 adapter tests共同证明不能继续I/O。

### Timeout 与 shutdown

- handshake timeout：默认 5 秒，覆盖 SOCKS/SS first authenticated header。
- direct connect timeout：默认 10 秒。
- idle timeout：默认 300 秒；任一方向成功 forward 至少 1 byte 才重置。
- graceful shutdown：收到 Ctrl-C/平台等价 signal 后立即停止新 accept，关闭
  listeners，允许现有 flows drain 最多 30 秒；deadline 后取消并终止剩余 task，
  `JoinSet` 必须全部 reap。
- `shutdown_grace_ms = 0` 表示立即取消，但仍等待所有 task termination，不表示
  detached abort。
- runtime deadline直接使用Tokio monotonic `Instant`/`timeout_at`，不依赖
  crypto-owned ADR-0002 `Clock`。`ferrum2-runtime` test-only Tokio features启用
  `test-util`并使用paused time；不以wall-clock sleep作为唯一证据。

### SOCKS success/failure semantics

`ferrum2-client` 在到 Shadowsocks server 的 IPv4 TCP connect、取得该 socket 的
local IPv4 endpoint 与完整 request first-write 成功后发送 SOCKS5 success。
success reply 的 `BND.ADDR/BND.PORT` 必须是这个 client→Shadowsocks-server
socket 的 local endpoint；若 endpoint 无法取得或不是 IPv4，则关闭该 socket并在
success 前发送 general failure。SIP022 没有 server target-connect acknowledgement；
因此 server 后续 target refusal 只能表现为 SOCKS stream 随后的 EOF/RST，并记录
closed failure class，不能回写第二个 SOCKS failure reply。

若 client 在 SS open/first-write 前失败，则 `SocksReplyPending` 按 RFC 1928 映射
并发送一次 failure reply。所有 request-stage failure reply 使用 IPv4
`BND.ADDR=0.0.0.0`、`BND.PORT=0`；reply owner保证 success/failure 至多一次。

### Tracing contract

日志是 stderr 上的 newline-delimited JSON。每个 event 只允许：

- `timestamp`、`level`、`event`
- `role = client|server`
- `transport = tcp`
- `stage = config|listen|socks5|shadowsocks|direct|relay|metrics|shutdown`
- `outcome = accepted|completed|rejected|failed|cancelled|timeout`
- `reason` 使用与 spec 对齐的 closed error enum
- opaque process-local monotonically assigned `session_id`
- duration 和 byte counts

不得记录 destination、peer-controlled hostname、PSK、subkey、salt、nonce、raw
config、raw frame、自由格式 source error。`logging.level` 只控制 closed level，
不接收任意 module filter string。

### Prometheus contract

`ferrum2-observability` 只拥有 `prometheus-client` registry、typed families和text
encoding，不依赖Tokio、不bind socket。registry 是显式 owner，由 composition
传入 instrumented components，不使用 process-global recorder。固定 metrics 为：

- `ferrum2_tcp_connections_total{role,inbound,outcome}` counter
- `ferrum2_tcp_connections_active{role,inbound}` gauge
- `ferrum2_tcp_failures_total{role,stage,reason}` counter
- `ferrum2_tcp_bytes_total{role,direction}` counter
- `ferrum2_tcp_replay_entries` gauge
- `ferrum2_tcp_replay_rejections_total{reason}` counter
- `ferrum2_tcp_forced_shutdown_total{role}` counter

labels 全部由 closed Rust enums编码。`inbound = socks5|shadowsocks`；
`direction = inbound_to_outbound|outbound_to_inbound`；`reason` 来自 spec 固定集合。
target、peer、port、session ID、method input、error string 和 secret 永不成为 label。
用大量不同 destination 运行相同事件时 series 集合必须完全不变。

metrics table 缺失时不创建 endpoint。存在时，`ferrum2-runtime` 在 config
validation之后启动一个supervisor-owned loopback listener；它接收composition提供
的`Fn() -> encoded text` renderer，不依赖observability concrete crate。listener
最大16个active request permits，header timeout 2秒，总request header cap 1024
bytes，只接受`GET /metrics`，其他请求返回bounded error后关闭。HTTP响应由runtime
的最小Tokio parser/write path完成，不为M0引入Hyper或后台exporter task。

### Deterministic lifecycle evidence seam

测试 build 提供只读 owner registry/counters：active supervisor children、connection
tasks、owned buffers、permits、listeners 和 forced shutdown count。production 不
暴露管理 API。lifecycle test 同时用 registry 回零、socket可重新 bind 和
`JoinSet` empty 作为直接证据；RSS 等统计不能单独判定通过。

## Consequences and tradeoffs

### Positive

- task、socket、buffer、permit 和 metrics listener 都有唯一 owner。
- 无 data channel 的 relay 直接继承 TCP backpressure，减少 per-frame allocation。
- closed tracing/metric schema 可做 snapshot 与 cardinality 测试。

### Negative

- 一个 connection task 内的双向 state machine 比简单双 `spawn` 更需要谨慎处理
  half-close 和 fatal cancellation。
- minimal HTTP exposition 只支持 `/metrics`，不是通用 HTTP server。
- M0 deterministic 100-cycle proof 不等同 M4 的 10,000 idle/RSS 性能资格。

## Compatibility and upstream divergence

reference clients/servers只参与 TCP wire，不能改变 ferrum2 SOCKS optimistic-success
contract。M3 可以 additive 稳定更多 operational fields，但不得在没有 migration
spec 时改名或让 destination 进入 labels。

## Migration and rollback

无持久 runtime/metric state。回滚关闭 listeners、drain/terminate tasks 后回退
integration commit。改变 task topology、data channel、metric name/labels 或 close
semantics 需要新 ADR。

## Verification plan

- M0-LIFE-001～005：backpressure、timeout/cancellation/listener failure、
  half-close、graceful shutdown、100-cycle cleanup。
- M0-OBS-001～003：JSON/redaction、metrics names/types/cardinality 与 runtime
  endpoint bounds。
- M0-E2E-001～002：真实二进制 success、target/protocol failure semantics。
- workflow quick/full 在同一 integrated commit 通过。

## References

- `AGENTS.md`
- `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`
- `docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md`
