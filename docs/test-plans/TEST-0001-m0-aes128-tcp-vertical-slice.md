# TEST-0001: M0 AES-128-GCM TCP 安全纵切

- **Status:** Approved
- **Milestone:** M0
- **Spec:** `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`

## Scope and test seams

本计划证明 SPEC-0001 AC-01～AC-12；required command 缺失、未运行、ignored 未显式
执行、环境不可用或 evidence 不完整都不是 pass。

M0 建立以下 production-shaped test seams：

- protocol `ScriptedClock`：wall 与 replay monotonic 时间独立推进；runtime timeout
  tests使用Tokio `test-util` paused time，不导入crypto Clock。
- `ScriptedRandom`：固定 salt/padding、重复值、失败和 nonce边界。
- `RecordingConnector`：调用次数、顺序、target category、forwarded bytes。
- `RecordingReplayStore`/store snapshot：check/insert/purge 的线性化与 entry count。
- `RecordingHeaderIo`：每次底层 read/write 的 call count、requested/returned length。
- `FrameBufferFactory`/`BufferObserver`：只记录安全 buffer capacity 请求；不用自定义
  global allocator，也不引入 `unsafe`。
- test-only `OwnerRegistry`：supervisor child、connection task、buffer、permit、
  listener 和 forced-shutdown counters。
- process harness：ephemeral ports、temporary config、readiness deadline、bounded
  stdout/stderr、child kill-on-drop、socket rebind。
- native socket probe：对不同 first-read failure 比较已批准的 RST close class。

protocol fake adapters与production adapters必须走同一泛型path；runtime paused
timer与production使用相同Tokio timeout code。mock只能观测capability，不得绕过
production validation/state transition。

Provider-neutral required job names：

```text
m0-host-quick
m0-security
m0-lifecycle
m0-local-e2e
m0-integration-full
m0-msrv
m0-windows-msvc
m0-linux-gnu
m0-linux-musl
m0-interop-sing-box
m0-interop-shadowsocks-rust
```

所有 test commands 从 repository root 执行。测试 harness package 名固定为
`ferrum2-m0-harness`。

## Acceptance-criteria evidence matrix

| Test ID | Spec criterion | Evidence/test | Level | Required job/command |
|---|---|---|---|---|
| M0-WS-001 | AC-01 | workspace members、crate DAG、core purity、`LocalEndpoint`/consuming reply ownership | contract/static | `cargo test -p ferrum2-m0-harness --test architecture --locked` |
| M0-WS-002 | AC-01/12 | exact direct versions、lock、GPL metadata、publish false、unsafe forbid、license provenance | static/build | `cargo test -p ferrum2-m0-harness --test workspace_policy --locked`；`cargo tree --workspace --locked` |
| M0-MSRV-001 | AC-01/11 | Rust 1.85.0 resolved graph | build/test | `cargo +1.85.0 check --workspace --all-targets --locked`；`cargo +1.85.0 test --workspace --locked` |
| M0-CFG-001 | AC-02 | 两 binary valid offline config | process integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked valid` |
| M0-CFG-002 | AC-02 | offline path 零 listener/connector/task 副作用 | process integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked no_side_effects` |
| M0-CFG-003 | AC-02/12 | config negative matrix与 secret redaction | parameterized integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked invalid_matrix` |
| M0-CLI-001 | AC-02 | help/version、stdout/stderr、exit taxonomy | process integration | `cargo test -p ferrum2-m0-harness --test cli_contract --locked` |
| M0-CRYPTO-001 | AC-03 | BLAKE3 official derive-mode vectors | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked blake3` |
| M0-CRYPTO-002 | AC-03 | 两个固定NIST AES-128-GCM cases + corrupted-tag reject | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked aes128_gcm` |
| M0-CRYPTO-003 | AC-03/12 | SIP022 KDF output、key truncation与nonce-counter fixture | unit/KAT | `cargo test -p ferrum2-crypto --test sip022_vectors --locked` |
| M0-CRYPTO-004 | AC-03 | redacted secret、explicit-clear seam、entropy failure、salt collision、nonce overflow | unit/negative | `cargo test -p ferrum2-crypto --test secret_entropy --locked` |
| M0-PROTO-001 | AC-04 | type/frame/address/padding/initial-payload bounds table | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked bounds` |
| M0-PROTO-002 | AC-04 | 每个 authenticated chunk bit flip与 truncation | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked auth` |
| M0-PROTO-003 | AC-04/05 | timestamp `±30`/`±31` | fake-clock unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked timestamp` |
| M0-PROTO-004 | AC-04 | S0-S3 reject 前 connector/forward/accepted/replay mutation 全零 | instrumented integration | `cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked` |
| M0-PROTO-005 | AC-04 | fixed buffer cap；无 peer-sized reserve | safe buffer-observer unit | `cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked` |
| M0-PROTO-006 | AC-04/12 | 有独立provenance的非官方request/response composite wire fixture | protocol KAT | `cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked` |
| M0-REPLAY-001 | AC-05 | invalid 不 poison；valid same salt first accept/second reject | fake-state unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact` |
| M0-REPLAY-002 | AC-05 | 64-way duplicate 原子性 | concurrency | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked concurrent` |
| M0-REPLAY-003 | AC-05 | 59.999/60s retention与 wall rollback | fake-clock/state | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked retention` |
| M0-REPLAY-004 | AC-05 | capacity full fail closed，无 live eviction | state unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked capacity` |
| M0-DETECT-001 | AC-06 | single underlying I/O + detection时恰好一次`mark_abortive`并terminal | instrumented transport | `cargo test -p ferrum2-shadowsocks --test detection_prevention --locked` |
| M0-DETECT-002 | AC-06/11 | short byte/bad auth/type/time/length 相同 native close class | native process/socket | `m0-windows-msvc` 与 `m0-linux-gnu` 各运行 `cargo test -p ferrum2-m0-harness --test detection_probe --locked` |
| M0-DETECT-003 | AC-06 | runtime `AbortiveClose`只在mark时设置zero linger；normal paths不设置 | runtime socket integration | `cargo test -p ferrum2-runtime --test abortive_close --locked` |
| M0-BIND-001 | AC-06 | response full request-salt equality，bad binding不 forward | protocol integration | `cargo test -p ferrum2-shadowsocks --test response_binding --locked` |
| M0-SOCKS-001 | AC-07 | connector在first-write前存local endpoint；success bytes为`05 00 00 01`+该IPv4/port；双向 bytes | unit/integration | `cargo test -p ferrum2-socks5 --locked`；`cargo test -p ferrum2-m0-harness --test local_e2e --locked success` |
| M0-SOCKS-002 | AC-07 | auth/cmd/domain/IPv6/malformed negative；每个 request-stage failure为`05 REP 00 01 00000000 0000` | unit/negative | `cargo test -p ferrum2-socks5 --test negative --locked` |
| M0-ENDPOINT-001 | AC-07 | `local_addr`恰好查询一次；error/non-IPv4时零 SIP022 first-write，composition发精确general failure | cross-crate ordering | `cargo test -p ferrum2-runtime --test local_endpoint --locked`；`cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_error_before_write`；`cargo test -p ferrum2-socks5 --test negative --locked general_failure`；`cargo test -p ferrum2-client --locked local_endpoint_failure` |
| M0-E2E-001 | AC-07 | 两真实 binary local echo + half-close + cleanup | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked success` |
| M0-E2E-002 | AC-07 | pre-success protocol failure与 post-success target refusal | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked failures` |
| M0-LIFE-001 | AC-08 | stalled writer停止 upstream read；buffer/permit cap | deterministic I/O | `cargo test -p ferrum2-runtime --test backpressure --locked` |
| M0-LIFE-002 | AC-08 | handshake/connect/idle timeout、cancel、listener failure | fake-time integration | `cargo test -p ferrum2-runtime --test lifecycle --locked` |
| M0-LIFE-003 | AC-07/08 | one-way EOF后 reverse drain | integration | `cargo test -p ferrum2-runtime --test half_close --locked` |
| M0-LIFE-004 | AC-08 | graceful drain/deadline/forced termination | process/integration | `cargo test -p ferrum2-runtime --test shutdown --locked` |
| M0-LIFE-005 | AC-08 | 100 mixed success/failure/cancel cycles 回基线 | deterministic repetition | `cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked` |
| M0-OBS-001 | AC-09 | JSON schema + sentinel secret/destination scan | integration/snapshot | `cargo test -p ferrum2-observability --test tracing_contract --locked` |
| M0-OBS-002 | AC-09 | exposition names/types/labels/cardinality | integration/snapshot | `cargo test -p ferrum2-observability --test metrics_contract --locked` |
| M0-OBS-003 | AC-09 | runtime-owned `/metrics` permits/timeout/header/method bounds | runtime integration | `cargo test -p ferrum2-runtime --test metrics_endpoint --locked` |
| M0-INT-001 | AC-10/12 | ferrum client→sing-box server | required external E2E | `cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_sing_box` |
| M0-INT-002 | AC-10/12 | ferrum client→shadowsocks-rust server | required external E2E | `cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_shadowsocks_rust` |
| M0-INT-003 | AC-10/12 | sing-box SOCKS client→ferrum server | required external E2E | `cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact sing_box_client` |
| M0-INT-004 | AC-10/12 | shadowsocks-rust client→ferrum server | required external E2E | `cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact shadowsocks_rust_client` |
| M0-PLAT-001 | AC-11 | Windows MSVC release build + artifact config run | native build/run | `m0-windows-msvc` commands in Compatibility matrix |
| M0-PLAT-002 | AC-11 | Linux GNU release build + artifact config run | native build/run | `m0-linux-gnu` commands in Compatibility matrix |
| M0-PLAT-003 | AC-11 | Linux musl release build + artifact config run/link evidence | build/run | `m0-linux-musl` commands in Compatibility matrix |
| M0-GATE-001 | AC-11 | authoritative quick gate | repository gate | `workflow.toml` `[validation].quick`，每项 exit 0 |
| M0-GATE-002 | AC-11 | authoritative full gate | integration gate | `workflow.toml` `[validation].full`，每项 exit 0 |
| M0-SCOPE-001 | AC-12 | fixed-baseline diff/provenance/non-goal audit | automated + Architect/QA review | `git merge-base --is-ancestor b41c6127b1834ebd97246451fd92bafea50cb205 HEAD`；`git diff --check b41c6127b1834ebd97246451fd92bafea50cb205...HEAD`；`cargo test -p ferrum2-m0-harness --test scope_audit --locked`；`cargo tree --workspace --locked` |

## Unit tests

### Workspace and config

- `architecture` 读取 `cargo metadata`，断言十个 members 精确、DAG 不含反向边；
  `core` 不含 Tokio/TOML/concrete package。
- `workspace_policy` 断言 direct versions/features与 ADR-0001 exact 相等、所有 project
  package继承 license/publish/lints、`Cargo.lock` tracked。完整 `cargo tree` 做人工
  provenance/license sign-off，不以“能编译”代替。
- config table覆盖每个 missing/unknown field、上下界/界外值、port 0、non-loopback
  metrics、internal endpoint equality、method/base64/key/file-size/UTF-8。

### Crypto and protocol

- primitive vector测试逐 case显示 vector ID，不在失败输出显示 runtime secret。
- crypto KDF/nonce fixture逐字段断言full 32-byte BLAKE3 output、used first
  16 bytes、zero nonce、carry和overflow。
- protocol composite fixture由`ferrum2-shadowsocks`测试逐字段断言每个nonce、
  plaintext/ciphertext/tag与完整request/response first-write wire bytes；该fixture
  明确不是官方SIP022 KAT。
- primitive input选择固定为ADR-0004的BLAKE3 `input_len=0,1,1024` rows和两个
  明列NIST numeric cases；不得由Engineer替换为“任意几个能过的vector”。
- composite input、generator path和provenance fields完全固定为ADR-0004；test
  runtime只读取并断言committed bytes，不更新fixture。
- nonce测试从 zero开始、跨 byte carry、最终 overflow；overflow前后不输出/接受
  重复 nonce。
- `local_endpoint`用可脚本化socket inspector覆盖成功、lookup error与IPv6结果：
  每案恰好一次查询；后两案不返回stream。`connector_error_before_write`断言这些
  connect errors使`HeaderIo` write count保持0；SOCKS与client composition tests
  再断言最终reply恰好为`05 01 00 01 00000000 0000`且只发送一次。
- protocol negative table至少包括：每个 chunk tag bit flip、0..完整长度的关键
  truncation points、type 0/1反转、ATYP、port 0、padding 901、padding overrun、
  empty padding+payload、length arithmetic、trailing/under-consumed header、
  response binding mismatch。

### Replay and ordering

- timestamp table：`now-31` reject、`now-30` accept、`now` accept、
  `now+30` accept、`now+31` reject。
- invalid auth/type/time/address/padding 不插入；随后同 salt合法 request必须能成为
  first success。
- 64 tasks barrier同步提交同一合法 header，结果精确 `1 accepted + 63 replay`。
- monotonic `59.999s` 不 purge，`60.000s` 可 purge；wall clock任意回退不改变。
- capacity装满 live entries后新 salt返回 `ReplayCapacity`，原 entries仍可检测。
- `RecordingConnector`/metrics/forward recorder断言完整 semantic success之前全零。

## Integration and interoperability tests

### Local product path

`local_e2e` 每个 case用 temporary directory、ephemeral loopback listeners 和
synthetic config启动真实 `ferrum2-server`/`ferrum2-client`：

1. SOCKS greeting + IPv4 CONNECT，并从真实 client→SS socket 读取 local IPv4
   endpoint，逐 byte断言 success reply 的 `BND.ADDR/BND.PORT`。
2. client→echo 至少两个不同边界的 payload，echo→client bytes逐 byte相等。
3. client write-half close 后仍收到 target reverse payload与 EOF。
4. child、ports、temp secrets和capture在 case终止时清理。

failure cases分开断言：

- client 无法连接 SS server：只发一次 pre-success SOCKS failure，并断言
  `ATYP=0x01`、`BND.ADDR=0.0.0.0`、`BND.PORT=0`。
- protocol first-write/read/auth failure：统一 close且没有 target accept。
- server target refusal：SOCKS success 已发，随后 EOF/RST；不期待第二个 SOCKS reply。

`ferrum2-m0-harness`不链接任何concrete ferrum2 crate。required job先运行
`cargo build --workspace --bins --locked`，harness从metadata target directory定位
当前platform binaries；artifact缺失即失败。

### External interoperability

四个 M0-INT tests默认 `#[ignore]` 只为防止 host quick 隐式依赖外部 binary；required
jobs必须用 `--ignored --exact` 显式执行。test读取 `tests/interop/versions.toml`，
要求 runner provision的 binary path存在且 version/artifact SHA-256完全匹配。
缺 env/path、下载失败、checksum/version mismatch、readiness timeout、child crash
或 case timeout直接失败；不得 `return Ok(())`、fallback latest 或把 ignored 状态
报告为 pass。

每个 case验证 TCP-only AES-128、双向 payload、half-close、reference进程清理。
case timeout 60 秒，readiness 10 秒，stdout/stderr各 cap 256 KiB；超限截断并标记，
kill-on-drop。只保存 sanitized diagnostics。

## Negative and error-path tests

- config：I/O、oversize、UTF-8、syntax、unknown/missing、range/cross-field、method/key。
- SOCKS：bad version、no acceptable auth、short greeting/request、unsupported command/
  ATYP、port 0。
- protocol：short first read/write、tamper/truncation、bad type/time/length/address/
  padding/binding、random/clock failure、nonce overflow。
- runtime：listen failure、connect refused/unreachable/timeout、idle timeout、relay I/O、
  signal/cancel、grace deadline。
- 每个 negative case断言只影响当前 flow（listener failure除外），并断言 exact
  closed reason、无 panic、无 secret/raw source error。

## Security tests

- sentinel values覆盖 raw PSK text、decoded key hex、derived key、request/response
  salt、nonce、raw config、IPv4 destination；扫描 stdout、stderr、captured tracing、
  error chain、panic hook capture和 Prometheus exposition，匹配数必须为零。
- metrics cardinality：至少 1,000 个不同 destination驱动相同结果，metric
  name+label-set集合与单 destination完全相等。
- native detection probe向 first-read逐 byte关闭并发送 bad tag/type/time/length；
  每类观察同一批准的 RST class，target accept count 0。Windows与Linux GNU为 M0
  blocking；musl完整 close matrix留 M3。
- fixture checksum/provenance在测试前验证；production code不能包含 fixture-only
  key、scripted RNG 或 bypass。

## Concurrency, race, and soak tests

- replay 64-way barrier test重复至少 20轮，不能出现0或>1 accepted。
- stalled writer使用受控容量 transport：达到 buffer cap后 upstream read count不再
  增长，恢复 writer后无丢字节。
- lifecycle用 paused/fake time，不使用长 wall sleep；每个 timeout测试在固定 step
  后 owner registry回零且 socket可重绑。
- `lifecycle_cycles` 至少100轮，包含 success、auth reject、connect failure、cancel
  和 forced shutdown；末尾 task/listener/buffer/permit counters等于起始值。
- M0 不以 ThreadSanitizer/RSS/长 soak为 pass条件；M3扩展平台 lifecycle，M4执行
  10,000 idle和资源稳定性资格。

## Compatibility and platform matrix

### Required references

| Case | Pin | Direction | Required result |
|---|---|---|---|
| M0-INT-001 | sing-box 1.13.14 | ferrum client → reference server | PASS |
| M0-INT-002 | shadowsocks-rust 1.24.0 | ferrum client → reference server | PASS |
| M0-INT-003 | sing-box 1.13.14 | reference client → ferrum server | PASS |
| M0-INT-004 | shadowsocks-rust 1.24.0 | reference client → ferrum server | PASS |

asset names/checksums/license policy见 ADR-0006；四行缺一即 M0 BLOCKED。

### Platform commands

三个 matching runners均使用：

```text
cargo +1.97.1 build --workspace --bins --release --locked --target <triple>
<client> --config <client-valid.toml> --check-config
<client> --config <client-invalid-key-length.toml> --check-config
<server> --config <server-valid.toml> --check-config
<server> --config <server-invalid-key-length.toml> --check-config
```

| Test | Triple / runner | Extra evidence |
|---|---|---|
| M0-PLAT-001 | `x86_64-pc-windows-msvc` / native Windows x86_64 + VS 2022 | PE artifact SHA-256、rustc/cargo/linker、valid 0/invalid 2、无 listener；M0-DETECT-002 PASS |
| M0-PLAT-002 | `x86_64-unknown-linux-gnu` / fixed x86_64 glibc Linux | image digest、required GLIBC symbols、artifact SHA-256、valid/invalid run；M0-DETECT-002 PASS |
| M0-PLAT-003 | `x86_64-unknown-linux-musl` / Linux + musl toolchain | `file`/`readelf` static-link evidence、artifact SHA-256、valid/invalid run |

每个 artifact对两个 binaries各运行 valid/invalid，共四次。只 `cargo check`、只构建
library、只看 artifact文件存在均失败。

MSRV在能够安装 1.85.0 的 host runner执行 M0-MSRV-001；1.97.1 current build不能
替代。BLAKE3 build backend/C compiler在三个 target evidence中记录。

## Performance and resource tests

M0 不设 throughput、10,000 idle、RSS/CPU或正式性能门；这些是 M4。M0 仍阻塞要求：

- fixed buffer/connection/replay/metrics caps测试；
- backpressure直接证据；
- 100-cycle deterministic cleanup；
- 不得以性能理由绕过 authentication、replay、bounds、backpressure或 unsafe policy。

## Test data, fixtures, and isolation

- 所有 repository fixtures使用 synthetic key/loopback endpoint，绝不使用 real PSK
  或 production data。
- primitive/protocol fixtures放在 `tests/fixtures/crypto/**` 与
  `tests/fixtures/sip022/**`。BLAKE3 commit/file hash/cases、NIST archive hash/
  numeric cases/public-information attribution，以及composite exact inputs/
  generator path均由ADR-0004固定；每组provenance metadata记录source、license、
  SHA-256和expected interpretation。
- composite SIP022 fixture明确写“unofficial”；expected bytes不由被测 production
  path运行时生成。
- config fixtures放 `tests/fixtures/config/**`；invalid fixture的 secret sentinel
  不得被 test failure message回显。
- external config、binary、logs、pcap和results只在 runner temp/
  `target/interop-tools`，不提交。每个 test独占 temp dir/ports并可并行运行。
- captured diagnostics在保存前扫描/redact；required evidence只记录 command category
  和 checksum，不记录 PSK/raw config。

## Scope and provenance audit

M0 的固定审计基线是 bootstrap 前的
`b41c6127b1834ebd97246451fd92bafea50cb205`。M0-SCOPE-001 先证明它是 `HEAD`
ancestor，再审计该 commit 到同一 integrated `HEAD` 的完整差异；不得改用移动的
branch name、人工挑选 path 或缩小 diff。

`scope_audit` 必须自动拒绝：不在 M0 tickets/control-doc allowlist 的路径、
`target/`/coverage/profile/pcap/log/result、可执行或压缩的 external artifact、
缺 `PROVENANCE.toml`/source/license/SHA-256/expected interpretation 的 fixture，
以及 production tree 中 fixture-only key/scripted RNG/bypass。随后 Architect 与
QA 对 `git diff --name-status --find-renames
b41c6127b1834ebd97246451fd92bafea50cb205...HEAD` 和
`cargo tree --workspace --locked` 明确签署以下 checklist：

- 所有变更落在批准的 M0 product/control ownership，未实现 AES-256、ChaCha、UDP、
  public UDP inbound、domain/DNS、multi-user/EIH、routing/management 或性能范围；
- 无 real secret、production endpoint、外部 binary、generated result或未审 fixture；
- dependency/member/method surface与 ADR-0001 相等，新增依赖均有license/provenance；
- T02/T03 fixtures与两个 reference pins的来源、hash、license和非分发策略完整。

## Exit conditions and known gaps

M0 test gate通过需要：

1. 表中 M0-WS～M0-SCOPE 每个 required ID有同一 integrated commit 的 PASS evidence。
2. `workflow.toml` quick/full所有命令实际运行且 exit 0。
3. 四项 interop与三项 platform smoke无 skip/缺失。
4. Architect与QA复核 spec符合性、security ordering、ownership和 evidence。
5. 未发现 committed external/generated artifact、real secret或M0 non-goal。

已知但明确延期：

- AES-256/ChaCha和完整地址/TCP matrix：M1。
- UDP/replay window/session limits：M2。
- 全平台长期 lifecycle和最终 operator stability：M3。
- throughput、10,000 idle与长期资源阈值：M4。

当前没有产品实现，所以上述测试均是 required future evidence，不是本次 plan 已通过
的测试。runner/provider缺失会使对应 gate BLOCKED，不会转换为 waiver。
