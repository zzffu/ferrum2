+++
id = "M0-T07"
title = "Compose the client and server binaries and prove the local vertical slice"
milestone = "M0"
status = "in_progress"
priority = "P0"
blocked_by = ["M0-T03", "M0-T04", "M0-T05", "M0-T06"]
owns = [
  "bins/ferrum2-client/src/cli.rs",
  "bins/ferrum2-client/src/main.rs",
  "bins/ferrum2-client/src/run.rs",
  "bins/ferrum2-client/Cargo.toml",
  "bins/ferrum2-server/src/cli.rs",
  "bins/ferrum2-server/src/main.rs",
  "bins/ferrum2-server/src/run.rs",
  "bins/ferrum2-server/Cargo.toml",
  "tests/m0-harness/src/local_support/**",
  "tests/m0-harness/tests/config_cli.rs",
  "tests/m0-harness/tests/cli_contract.rs",
  "tests/m0-harness/tests/local_e2e.rs",
  "tests/m0-harness/tests/lifecycle_cycles.rs",
  "tests/m0-harness/tests/detection_probe.rs",
  "tests/m0-harness/tests/workspace_policy.rs",
  "tests/m0-harness/Cargo.toml",
  "Cargo.lock",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-CFG-001 through M0-CLI-001 pass against both real binaries, including exact offline output and zero listener, connector, metrics, tracing, or task side effects",
  "M0-E2E-001 and both M0-SOCKS criteria pass through two independent processes, a SOCKS5 peer, and an IPv4 echo target with byte equality and half-close",
  "Composition passes the opened Shadowsocks stream stored LocalEndpoint into the consuming SOCKS success reply; it does not substitute the SOCKS listener or remote endpoint",
  "M0-ENDPOINT-001 client composition maps a LocalEndpoint or connect general error to one exact 05 01 00 01 00000000 0000 reply and performs no protocol first-write",
  "M0-E2E-002 fixes pre-success protocol failure versus post-success target-refusal EOF or reset semantics and proves target accept count remains zero on unauthenticated requests",
  "M0-LIFE-005 combines exactly 100 black-box cycles split 20 each across success/auth reject/connect failure/cooperative cancel/forced termination with T06 direct counters and binary-private production-used registry composition evidence",
  "Every black-box cycle timed-waits its child, rebinds the exact proxy/metrics/target addresses, removes its temp path, and returns the harness child registry to baseline; private composition tests first witness live nonzero runtime counters and then baseline, with forced_shutdowns exactly +1",
  "M0-DETECT-002 runs exactly 47 native connections on each required native platform: 43 valid fixed-region prefixes plus independently authenticated auth/type/time/length rows; every row resets rather than EOF and leaves target accepts at zero",
  "The independent detection generator uses only workspace-inherited aes-gcm/blake3 test primitives, never a ferrum2 package; the authenticated zero-length row maps to AddressBounds",
  "M0-ADAPT-001 and M0-ADAPT-002 prove the client TokioConnector and both binaries' TokioTransport/TokioFramed mechanical delegation, initialized ReadBuf handling, fixed error mapping/source redaction, role/call-site typed observability mapping including Normal, configured-server versus application-target separation, and direct-connect-before-initial-payload-forward ordering",
  "The server connection owner writes Session.initial_payload completely and exactly once after target connect and before ordinary relay; connect or prefix-write failure never starts relay, and ServerFlow never repeats the payload",
  "Client composition applies independent configured-server connect and fresh request-first-write deadlines from validated config, proves the 10-second/5-second defaults plus non-default values through ADR-0012's opaque phase capability, and sends SOCKS success only after first-write completion",
  "Prefix and ordinary relay accounting includes only successful nonzero application writes, retains direction-separated partial counts on error/idle/cancel, and never double-counts prefix bytes",
  "ADR-0013 adds exactly one workspace-inherited Tokio test-util dev edge to each binary, leaves both normal declarations and the production feature graph unchanged, and produces no Cargo.lock hunk beyond ADR-0011's harness edges",
]
+++

# M0-T07: Compose the client and server binaries and prove the local vertical slice

## Outcome

将已审核的deep modules组合为独立`ferrum2-client`/`ferrum2-server`，以真实process
证明offline config、SOCKS5→SIP022→direct echo、failure ordering、half-close和
repeated cleanup。

## Context

这是T03/T04/T05/T06的汇合票。composition root不得重新实现protocol/runtime
规则；发现contract不匹配时停止并回到对应上游ticket/ADR，而不是在binary中shim。

## In scope

- 两binary `main`/run composition、Tokio multi-thread runtime和signal wiring。
- validated config到providers/listeners/metrics/supervisor的construction order。
- client binary-local `TokioConnector`及两个composition root内的
  `TokioTransport`/`TokioFramed` newtype adapters，将已审核的opaque SS flow接入
  未修改的runtime `relay_lifecycle`。
- server direct connect后、ordinary relay前的bounded
  `Session.initial_payload`完整一次性forward。
- process harness local support、ephemeral echo/recording target和child cleanup。
- real-binary config CLI、local E2E、failure、lifecycle cycles与native detection probe。
- ADR-0011限定的harness `aes-gcm`/`blake3` dev-dependencies、精确两条harness
  lock edges和CRLF-safe workspace-policy evidence。
- ADR-0013限定的两个binary `Cargo.toml` exact Tokio `test-util` dev declarations、
  production/test feature-tree boundary与zero-additional-lock-delta evidence。

## Out of scope

- external reference download/interop、target platform matrix（T08）。
- method/transport/address范围扩展。
- root/其他member manifest（ADR-0013两个binary manifests的exact dev declarations
  除外）、除`ferrum2-m0-harness`精确两条edge之外的lock hunk，或任何production
  dependency/shared module修改。
- push/publish/release。

## Implementation notes and constraints

- `--check-config`必须在任何subscriber/runtime/listener/provider side effect前return。
- client SOCKS success时机与SPEC-0001一致，并传入opened SS stream存储的
  `LocalEndpoint`；server target failure不产生第二reply。
- client composition把validated `client.server`交给`ClientTcpOutbound`作为固定
  upstream endpoint；`TokioConnector`只机械委托，不得用SOCKS application target
  替换该endpoint。
- binary在opaque `connect_server` future外应用validated configured
  `connect_timeout`，并只在成功后为consuming request-first-write future启动fresh
  validated `handshake_timeout`。默认值为10秒/5秒，但测试必须用non-default values
  杀死hardcoding。connect timeout是pre-success `ConnectTimeout`；handshake
  timeout是binary `Reason::HandshakeTimeout`、normal drop、abortive 0；
  first-write真实错误保持Detection。不得用Notify/heuristic/raw transport shim。
- 两个binary保留normal `tokio.workspace = true`，且各自在
  `[dev-dependencies]`只新增
  `tokio = { workspace = true, features = ["test-util"] }`。不得修改root Tokio
  features、normal edge、version/default/source/path或`Cargo.lock`；paused-time
  tests不得依赖其他package的dev edge。
- server connector Pending/failure时不得poll或forward `Session.initial_payload`；
  success后用bounded writes保持原byte sequence完整一次，prefix write失败停止flow。
- listener/supervisor拥有所有child；harness必须kill-on-drop并避免固定ports。
- `run`必须调用同一个private `run_with_registry` production path；composition tests
  必须观察registry live witness后回baseline，不能以process exit/rebind声称看到了
  进程内counter。
- server prefix loop只有successful nonzero write重置idle；timeout/cancel/write-zero/
  error保留partial count且不进入relay。runtime relay failure stats与prefix count只在
  binary instrumentation boundary合并一次。
- instrumentation只调用typedobservability API，不加入free-formtarget/error labels。
- 每个`DetectionReason`、`ProtocolReason`、`TransportPhase`、
  `ConnectErrorKind`及`Normal`只按ADR-0010 exact table映射
  `Reason`/stage/outcome；client configured-SS Connect为`shadowsocks/failed`，
  server direct-target Connect为`direct/failed`，Normal为
  `relay/completed/no reason`。
- native detection probe失败是contract evidence blocker，不能标记flaky/skip。
- adapters只委托connector/poll、stored endpoint、abortive与ADR-0010 exact closed
  error/observability mapping；不得用string或自定义heuristic重新分类，不得
  physical split/reunite transport，不得引入per-flow mutex、channel或direction
  task，不得复制frame/cipher/replay/binding/allocation/protocol state。

## Validation commands

```bash
cargo build --workspace --bins --locked
cargo metadata --locked --format-version 1
cargo tree -p ferrum2-client --locked -e normal,build,features -i tokio
cargo tree -p ferrum2-server --locked -e normal,build,features -i tokio
cargo tree -p ferrum2-client --locked -e all,features -i tokio
cargo tree -p ferrum2-server --locked -e all,features -i tokio
cargo build -p ferrum2-client --bin ferrum2-client --release --locked
cargo build -p ferrum2-server --bin ferrum2-server --release --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo test -p ferrum2-m0-harness --test cli_contract --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked
cargo test -p ferrum2-m0-harness --test detection_probe --locked
cargo test -p ferrum2-client --locked local_endpoint_failure
cargo test -p ferrum2-client --locked adapter_contract
cargo test -p ferrum2-client --locked phase_deadline_contract
cargo test -p ferrum2-client --locked lifecycle_composition_contract
cargo test -p ferrum2-server --locked adapter_contract
cargo test -p ferrum2-server --locked lifecycle_composition_contract
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

## Risks

- composition初始化顺序可能破坏offline/no-listener guarantee。
- optimistic SOCKS success容易与server target refusal错误映射。
- process tests若未严格分配/清理ports和children会产生flake或leak假阴性。

## Completion evidence

- Preserved branch: `codex/ticket/m0-t07`
- Partial checkpoint:
  `52dcdb00a82ed0ab07601f86a985de853c1df00f`
- Partial scope: both binary `src/{cli,main,run}.rs`、harness local support、
  `config_cli`、`cli_contract`、`local_e2e`; no manifest/lock、lifecycle/native probe
  或control-doc changes
- Partial gates: binary build、config CLI 3、CLI contract 3、local E2E 4、
  client endpoint 1、client adapter 5、server adapter 6、workspace fmt/check/test与
  strict Clippy均exit 0；worktree clean
- Resume checkpoint:
  `78876c6fc8616e6b5f2d5bf3b82150779fff9943`
- Resume scope/evidence: 保留上述partial并增加ADR-0011 exact harness dependency/
  lock policy、native 47-case detection probe、exact 100-process lifecycle cycles、
  binary-private registry与T06 failure-stats consumer migration；两个binary
  manifests仍未修改，worktree clean
- Candidate commit:
  `5ac8f1b7894256caf1e0200befbcc32af9469342`
- Candidate gates: 全部ticket commands及workflow quick/full均exit 0；
  lifecycle为exact 100 cycles，native detection为exact 47 connections，
  workspace policy 16/16，client phase deadline 5/5，server lifecycle/prefix
  6/6；Accepted base与resume checkpoint均为ancestor，worktree clean
- Candidate review: QA PASS，24/24 ticket与4/4 full commands均exit 0；
  Architect BLOCK，唯一REQUIRED是cooperative-cancellation cycle只依赖raw
  connect/drop、10ms sleep与最终process kill，未deadline-bounded证明server已
  accept并完成该flow
- Repair 1/2 commit:
  `a9b0a56f8131f1db61701c5f50f7818a5664933a`
- Repair evidence: 只修改`lifecycle_cycles.rs`；旧row target-accept assertion
  两次RED为`WouldBlock`，修复后valid client→server→target flow在bounded
  target-accept ack后执行client `Shutdown::Both`/drop，并在cleanup前要求target
  EOF/reset；exact 5×20、local E2E、workspace quick/full均PASS
- Repair review: Architect与QA均PASS，无剩余BLOCKER/REQUIRED；
  repair-affected、quick与full commands全部重跑通过
- Current gate: **DONE**
- Integrated commit:
  `91516720e9acdc60597dd3596d6cbd33319d5a39`
- Integration evidence: exact two-parent merge；Team Lead与独立QA均按ticket顺序先
  build真实binaries，再完成quick 3/3、ticket 24/24与full 4/4；Architect final
  integration PASS，17个ticket paths与candidate blobs exact相同，base以
  fast-forward更新
- Publication: none
- Recovery reopen (2026-07-27): T08's required Rust 1.85.0 gate exposed
  `E0658` in `bins/ferrum2-server/src/run.rs` because the accepted T07
  composition used let-chain syntax unavailable on the pinned MSRV. The repair is
  restricted to an equivalent nested `if let`; behavior, APIs, manifests, lockfile,
  product scope, and wire contract remain unchanged. T08 stays blocked until this
  repair passes Engineer, Architect, QA, and integration gates.
