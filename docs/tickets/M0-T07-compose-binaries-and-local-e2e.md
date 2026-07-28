+++
id = "M0-T07"
title = "Compose the client and server binaries and prove the local vertical slice"
milestone = "M0"
status = "done"
priority = "P0"
risk = "high"
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
  "Every black-box cycle timed-waits its child, immediately bind-listens the exact proxy/metrics/target addresses under ADR-0015's Unix-reuse/default-Windows policy, removes its temp path, and returns the harness child registry to baseline; a live same-policy owner still excludes a contender; private composition tests first witness live nonzero runtime counters and then baseline, with forced_shutdowns exactly +1",
  "M0-DETECT-002 runs exactly 47 native connections on each required native platform: 43 valid fixed-region prefixes plus independently authenticated auth/type/time/length rows; every row resets rather than EOF and leaves target accepts at zero",
  "The current selected profile uses workspace-inherited aes-gcm/blake3 independent primitives and the ADR-0015 socket2 rebind-evidence edge; any ADR-0016 substitution preserves all 47 native rows, production-oracle independence, target accepts zero, and the authenticated zero-length AddressBounds mapping",
  "M0-ADAPT-001 and M0-ADAPT-002 prove the client TokioConnector and both binaries' TokioTransport/TokioFramed mechanical delegation, initialized ReadBuf handling, fixed error mapping/source redaction, role/call-site typed observability mapping including Normal, configured-server versus application-target separation, and direct-connect-before-initial-payload-forward ordering",
  "The server connection owner writes Session.initial_payload completely and exactly once after target connect and before ordinary relay; connect or prefix-write failure never starts relay, and ServerFlow never repeats the payload",
  "Client composition applies independent configured-server connect and fresh request-first-write deadlines from validated config, proves the 10-second/5-second defaults plus non-default values through ADR-0012's opaque phase capability, and sends SOCKS success only after first-write completion",
  "Prefix and ordinary relay accounting includes only successful nonzero application writes, retains direction-separated partial counts on error/idle/cancel, and never double-counts prefix bytes",
  "The current selected profile keeps one workspace-inherited Tokio test-util dev edge in each binary and ADR-0011/0015's exact harness edges; any ADR-0016 substitution remains package-local and dev-only, leaves the production/release graph unchanged, and receives an exact lock and workspace-policy audit",
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
- ADR-0011经ADR-0015部分取代后的harness `aes-gcm`/`blake3`/`socket2`
  dev-dependencies、精确三条harness lock edges和CRLF-safe workspace-policy
  evidence。
- ADR-0013限定的两个binary `Cargo.toml` exact Tokio `test-util` dev declarations、
  production/test feature-tree boundary与zero-additional-lock-delta evidence。
- ADR-0016 equivalent-evidence记录：old claim、新seam、相同failure coverage、
  independence、platform、cleanup、exact ownership/candidate与invalidated gates。

## Out of scope

- external reference download/interop、target platform matrix（T08）。
- method/transport/address范围扩展。
- root/其他member manifest、当前selected profile之外的lock hunk或任何production
  dependency/shared module修改；只有执行前按ADR-0016映射并取得single-writer
  lease的exact test-only替代可作为本票窄例外。
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
  tests不得依赖其他package的dev edge。这是当前selected profile；替代只能在
  ADR-0016执行前amendment后使用，并必须同样杀死default/non-default hardcoding与
  wall-clock mutation且不污染production graph。
- server connector Pending/failure时不得poll或forward `Session.initial_payload`；
  success后用bounded writes保持原byte sequence完整一次，prefix write失败停止flow。
- listener/supervisor拥有所有child；harness必须kill-on-drop并避免固定ports。
- Client/server各自的binary-private listener constructor只在Unix bind前调用
  `set_reuseaddr(true)`；Windows保持default，任何平台不得启用`SO_REUSEPORT`。
  Proxy使用validated configured backlog，metrics保持16。Harness target/foreign/
  cleanup listeners从首次bind起镜像同一平台策略并完成bind+listen；live
  same-policy incumbent必须让contender失败。
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
- 100-cycle、47-row与same-policy rebind的当前helper/process布局可按ADR-0016作
  等强重组，但五类各20次、全部47语义rows、逐案target=0、逐cycle cleanup/rebind、
  internal-owner直接证据、immediate restart与live-owner exclusion不得减少。
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
- Historical `91516720` gate: **DONE**
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
- MSRV repair candidate:
  `50bf0b7b632333758fbaecde05dbe92b39171db3`
- MSRV repair integration:
  `123618f747771d6b0473c099f4c741ee4046fd9f`
- MSRV repair gates: exact two-parent merge；relative to coordination parent只修改
  `bins/ferrum2-server/src/run.rs`的等价nested `if let`（4+/4-），candidate与
  integration blob一致；Rust 1.85 build/check/workspace test（194/194）、
  focused server adapter/lifecycle、quick 3/3、full 4/4均exit 0。Team Lead、
  final Architect与independent QA均PASS；base以fast-forward更新，worktrees
  clean且`target/`已清理。
- Final recovery gate: **DONE**
- Recovery publication: none
- Readiness recovery reopen (2026-07-27): independent T08 QA's first
  `cargo +1.85.0 test --workspace --locked` failed in the exact 100-cycle
  lifecycle suite with `child exited before readiness`; focused 2/2 and the
  exact workspace rerun 204/204 passed, so the first failure was retained for
  diagnosis rather than waived.
- Readiness diagnosis branch: `codex/diagnose/m0-t08-lifecycle-flake`;
  3/3 MSRV、3/3 current serial and 4/4 parallel focused invocations passed
  (`0/1000` spontaneous cycle failures), while a deterministic foreign-port
  probe reproduced the failure path 1/1. Root cause is test-harness TOCTOU:
  `unused_loopback` releases the reservation and ownership-blind
  `wait_for_bound` treats any `AddrInUse` as child readiness before the real
  child exits on bind collision. No product lifecycle defect or process/temp
  leak was found.
- Readiness repair branch: `codex/repair/m0-t07-readiness-ownership`;
  restricted to `tests/m0-harness/src/local_support/**` and
  `tests/m0-harness/tests/lifecycle_cycles.rs`.
- Readiness repair candidate:
  `1974935e3a6d86588a156be43f5ad45ca623330c`; retained reservations reach
  immediately before spawn、metrics identity readiness、max-three retry only
  after reaped child plus demonstrable foreign ownership、bounded hashed child
  diagnostics and exact five-by-twenty successful cycles. Intentional old-helper
  mutation RED；current lifecycle 3×3/3、MSRV lifecycle 3/3、focused regression、
  detection 2/2、local E2E 4/4、current/MSRV checks、strict Clippy、fmt and docs
  PASS. Pre-integration MSRV workspace test reaches the repaired lifecycle 3/3
  then fails only on the separate T08 CRLF workflow parser fixed on its repair
  branch.
- First readiness review: Architect **BLOCK** with three REQUIRED groups:
  the foreign-port regression bypassed the real spawn/readiness/retry path；
  metrics readiness used a blocking connect and generic Prometheus identity；
  second-child collision left its running sibling to unbounded `Drop` cleanup.
- Readiness follow-up candidate:
  `6139544465d5a5d0e88b02aeed3e0268da208def`, exact child of `1974935`;
  only the same two authorized harness files changed. It adds a bounded complete
  Ferrum metrics response, role-specific negative proxy probe and exact fresh
  failure-counter `0→1` causal identity under one absolute five-second deadline.
  The deterministic after-release mutation now traverses the real
  spawn/readiness/retry path, rejects Ferrum-looking and drip responders, reaps
  the failed child plus any started sibling, and verifies registry baseline,
  nonforeign exact rebind and temp-path removal before the successful retry.
  Exactly 20 successful cycles in each of five categories remain required.
- Follow-up Engineer/QA evidence: intentional marker-only mutation RED, then
  current and Rust 1.85 lifecycle 4/4 GREEN including the exact 100-cycle row；
  detection 2/2、local E2E 4/4、current/MSRV checks、fmt、strict Clippy and docs
  PASS. Independent QA **PASS_WITH_ACTIONS**: standalone quick/full fail only
  the separately owned pre-final-T08 CRLF workflow parser; combined integration
  must include T08 `49c63082` and rerun both gates.
- Follow-up Architect gate: **PASS** with no BLOCKER/REQUIRED; legacy
  `detection_probe` ownership-blind `wait_for_bound` remains advisory and outside
  this lifecycle repair.
- Pre-hosted readiness recovery gate (subsequently closed by `51fb7327`):
  **REVIEW**；candidate `6139544` was approved for integration and still
  required combined same-SHA local, Architect and QA gates.
- Readiness recovery publication at that checkpoint: none
- Hosted-rebind reopen (2026-07-28): T07 `6139544` and T08 `49c63082` were
  integrated into exact `51fb7327af966cfc3f4a49058ea6bf2284009dcf`; local
  Team Lead, final Architect and independent QA gates passed, and that exact SHA
  was pushed only to `origin/codex/integration/m0`. GitHub Actions run
  `30301746374` attempt 1 failed four jobs at the same first Linux
  M0-LIFE-005 exact-rebind assertion (`EADDRINUSE`); later poisoned-lock rows
  were derivative. No task/child leak or protocol failure is waived.
- Hosted-rebind diagnosis: both binary-local `TcpSocket` listener constructors
  lacked Unix reuse-address, while the harness used a plain bind probe after
  real traffic. Product scope **PASS_WITH_ACTIONS** and Architect diagnosis
  **BLOCK** pending repair; ADR-0015 now defines Unix-only listener reuse,
  default Windows behavior, same-policy bind+listen evidence, live-owner
  exclusion and the exact `socket2` dev edge.
- Independent QA Linux reproduction: an offline Arch WSL current-toolchain
  build exited 0. The full lifecycle test and a second full-name `--exact`
  execution each exited 101 at the first `exactly_100...` cycle, failing client
  proxy rebind on `127.0.0.1:44221` and `127.0.0.1:45809` with
  `EADDRINUSE`; later rows only observed the poisoned test lock. No ferrum
  listener remained, while the failed port was in `TIME_WAIT`. An independent
  socket probe exited 0 and observed: default rebind in `TIME_WAIT` =
  `EADDRINUSE`；old/new Unix reuse-address = success；live same-policy contender
  = `EADDRINUSE`. WSL setup-only failures were retained separately: combined
  toolchain/temp target exit 101 `ENOSPC`, and a drvfs install timeout exit 124.
  All dedicated temp paths and owned processes were cleaned; integration
  worktree remained clean with `target/` absent.
- Hosted-rebind gate resolution: **PASS**. The bounded repair changed only the
  two binary `run.rs` listener constructors, harness local/lifecycle seams,
  `tests/m0-harness/Cargo.toml`, `Cargo.lock`, and `workspace_policy.rs`; it was
  integrated by `5969bfd`. Hosted lifecycle evidence passed at exact `5969bfd`
  in run `30322690937`, and the final exact `8318ef1` run `30331336772`
  attempt 1 also completed all six rendered results successfully. Both exact
  remote authorizations are exhausted; close mode performed no remote mutation.
