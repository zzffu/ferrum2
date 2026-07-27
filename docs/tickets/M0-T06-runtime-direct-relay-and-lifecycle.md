+++
id = "M0-T06"
title = "Implement bounded runtime, direct outbound, and lifecycle ownership"
milestone = "M0"
status = "done"
priority = "P0"
blocked_by = ["M0-T01"]
owns = [
  "crates/ferrum2-runtime/src/**",
  "crates/ferrum2-runtime/tests/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-LIFE-001 proves direct end-to-end backpressure, the fixed 16384-byte application buffers, configured semaphore bounds, and absence of data-plane queues",
  "M0-LIFE-002 and M0-LIFE-004 prove deterministic handshake, connect, idle, cancellation, listener-failure, graceful-drain, and forced-termination behavior with every JoinSet child reaped",
  "M0-LIFE-003 proves one-way EOF shuts down only the opposite writer and permits reverse-direction drain",
  "The DirectOutbound invokes its Connector only for validated IPv4 Sessions, and the detection-failure socket adapter applies zero linger only to the approved failure class",
  "The runtime connector queries local_addr exactly once after IPv4 connect and before returning, rejects lookup failure or non-IPv4, and stores the SocketAddrV4 in its core LocalEndpoint wrapper",
  "M0-ENDPOINT-001 runtime cases prove lookup error and IPv6 return no stream, so downstream protocol first-write cannot occur",
  "M0-DETECT-003 proves RuntimeTcpStream implements core AbortiveClose without importing a Shadowsocks type, mark_abortive alone sets zero linger, and ordinary EOF, failure, and shutdown do not",
  "M0-OBS-003 proves the supervisor-owned metrics listener enforces 16 permits, a 2-second header timeout, a 1024-byte request cap, and GET /metrics only without depending on observability internals",
  "ADR-0012 relay outcomes retain direction-separated RelayStats for success, I/O failure, idle timeout, and cancellation, counting only successful nonzero application writes",
  "Focused lifecycle tests prove partial-write-then-error, bidirectional partial failure, idle timeout, cancellation, and write-zero preserve exact completed counts without changing one-owner-task/two-buffer/no-channel topology",
]
+++

# M0-T06: Implement bounded runtime, direct outbound, and lifecycle ownership

## Outcome

交付supervisor building blocks、bounded listener/connection ownership、IPv4 direct
connector、无data channel双向relay、timeouts/half-close/shutdown和detection close
socket adapter。

## Context

本票不依赖concrete protocol，可以与T03并行。T07将runtime泛型实例化为client/server
真实流程并完成100-cycle/process evidence。

## In scope

- root supervisor/accept-loop abstractions、semaphore-before-accept和owned `JoinSet`。
- `DirectOutbound<Connector>`与recording connector adapters。
- one-owner-task relay futures、fixed buffers、backpressure与half-close。
- handshake/connect/idle/shutdown deadlines和listener failure propagation。
- socket2 zero-linger adapter、test-only owner registry/counters。
- generic bounded metrics listener/parser，接收composition提供的render closure，不依赖
  `ferrum2-observability`。
- unit/integration lifecycle tests。
- ADR-0012 relay failure outcome，携带terminal kind和failure前精确partial
  direction stats。

### Reopened narrow ADR-0012 repair

历史T06 completion evidence保持有效。本次只允许修改
`crates/ferrum2-runtime/src/**`与对应tests，使`relay_lifecycle`在normal、I/O、
idle和cancellation outcomes均保留`RelayStats`。计数点仍是successful nonzero
application `AsyncWrite` return；不得改变buffer size、task/future/channel topology、
backpressure、half-close、timeout值、connector、metrics schema、manifest/dependency
或产品范围。server initial-payload prefix loop仍由T07 binary-private composition拥有。

## Out of scope

- SIP022/SOCKS codecs、config parse、metrics schema。
- binary signal/composition process（T07）。
- routing、DNS、multiple upstreams、UDP。
- new task runner或manifest修改。

## Implementation notes and constraints

- ADR-0016只允许替换private registry/counter helper、test file或result-carrier
  spelling；one-owner-task/two-buffer/no-channel topology、partial stats、
  backpressure、half-close、timeout与shutdown语义保持本票规范。替代evidence仍须
  覆盖全部terminal/mutation并经Architect/QA执行前映射。
- 每flow一个spawnedowner task；relay directions不可另spawn。
- data plane无mpsc/channel/prefetch queue。
- permit在accept前取得并随socket/task生命周期释放。
- normal EOF/shutdown不设置zero linger；仅ADR-0004 detection class。
- connector在connect后、返回前查询并存储IPv4 local endpoint；失败/非IPv4以
  pre-first-write connect error返回，后续wrapper只读取存储值。
- fake/paused time测试必须断言registry回零和socket可重绑。
- partial stats必须逐方向保留，不计read-ahead、pending、write-zero、ciphertext或
  protocol overhead；failure kind与stats必须同时可检查。

## Validation commands

```bash
cargo test -p ferrum2-runtime --test backpressure --locked
cargo test -p ferrum2-runtime --test lifecycle --locked
cargo test -p ferrum2-runtime --test half_close --locked
cargo test -p ferrum2-runtime --test shutdown --locked
cargo test -p ferrum2-runtime --test metrics_endpoint --locked
cargo test -p ferrum2-runtime --test abortive_close --locked
cargo test -p ferrum2-runtime --test local_endpoint --locked
cargo clippy -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt -p ferrum2-runtime -- --check
```

## Risks

- select/cancellation ordering可能drop尚未flush的half-close方向。
- permit/listener/task owner关系错误会在failure/shutdown泄漏。
- zero linger误用于普通关闭会造成不必要数据丢失和可观察差异。

## Completion evidence

- Branch: `codex/ticket/m0-t06`
- Commit(s): `50f547f380d6c58d5538b6540fdc43cb29b5c89c`,
  repair 1/2 `721ed023703601d67dc2cfaad36d31502418373a`
- Architect verdict: initial **BLOCK**; repair re-review and assembled integration
  **PASS**
- QA verdict: initial **FAIL**; repair re-review and assembled integration
  **PASS**
- Integrated commit: `999d4f95a2d597fb283689b9306d2a6773af707d`
- ADR-0012 outcome repair:
  `756a379dc42919fb4fed9c476ec2bd3926201852` plus narrow test/rustdoc repair
  `0ef796907ef9699ba46a9c8fbdfeffdd5230b58f` on
  `codex/repair/m0-t06-relay-outcome`。Delayed-read mutation proof、全部9项ticket
  commands、package/all-features 33/33、strict Clippy/fmt与scope/lineage均PASS；
  final Architect/QA均**PASS**，先前coverage gap与rustdoc advisory均关闭。
- Repair integration merge/checkpoint:
  `2ce77082ed65bfe1a8707f8923f27dc75c2f5c6a`；组合Architect/QA均
  **PASS**，T03+T06 normal/all-features各97 tests通过。剩余workspace quick、
  binary-private registry和100-process evidence归T07，不是T06缺陷。
- Publication: none
