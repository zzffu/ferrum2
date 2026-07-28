# TEST-0001: M0 AES-128-GCM TCP 安全纵切

- **Status:** Approved
- **ADR-0010 amendment:** Approved
- **ADR-0011/0012 amendments:** Approved
- **ADR-0013 amendment:** Approved
- **ADR-0014 amendment:** Approved
- **ADR-0015 amendment:** Approved
- **ADR-0016 amendment:** Approved
- **Milestone:** M0
- **Spec:** `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`

## Scope and test seams

本计划证明 SPEC-0001 AC-01～AC-12；required command 缺失、未运行、ignored 未显式
执行、环境不可用或 evidence 不完整都不是 pass。

ADR-0016把下述具体test/probe/dependency组合定义为当前selected conformance
profile，而非永久唯一机制。替代必须在执行前记录old claim→new seam、相同正负向
coverage、independence、bounds、platform与cleanup，更新本计划/ticket mapping，
并在新exact candidate SHA上执行全部受影响gate。文档修改、旧SHA、skip、zero-test
或本机结果不能追认失败的required evidence。

带name filter的required Cargo command必须同时核对非零且精确的matched test
count；仅exit 0但运行0 tests仍为FAIL。新增crypto owner filter必须运行2 tests
（sealer/opener），T03 internal-flow filter必须运行4 tests（client/server nonce
mapping与encrypt/decrypt scratch capacity）。

M0 建立以下 production-shaped test seams：

- protocol `ScriptedClock`：wall 与 replay monotonic 时间独立推进；runtime与
  binary composition timeout tests使用Tokio `test-util` paused time，不导入
  crypto Clock。当前binary capability来自ADR-0013 exact dev-kind edges；等价替代
  仍必须package-local/dev-only且不得污染production graph。
- `ScriptedRandom`：固定 salt/padding、重复值、失败和 nonce边界。
- `RecordingConnector`：调用次数、顺序、target category、forwarded bytes。
- `RecordingReplayStore`/store snapshot：check/insert/purge 的线性化与 entry count。
- `RecordingTransportIo`：跨与production相同的`TransportIo` seam记录每次completed
  read/write、requested/returned length、fragment script、flush/shutdown与abortive
  count；`Pending` poll不伪计completed operation。
- `FrameBufferFactory`/`BufferObserver`：只记录安全的fixed usable-limit request、
  role与opaque storage identity；不用自定义global allocator，也不引入`unsafe`；
  同一flow多帧断言allocation count、identity稳定且无reserve/growth。
- `FlowObserver`：production为no-op；recording版本与
  `RecordingTransportIo`共享sequence recorder，只记录closed terminal event，
  直接证明terminal installation早于abortive call。
- T03 scripted adapter：通过与production相同的`TransportIo`/`PlainDuplex` seam
  观察bytes、fairness、backpressure、half-close与typed terminal；T07 binary unit
  tests另外覆盖client `TokioConnector`及两个composition root中的production
  `TokioTransport`/`TokioFramed` delegation与source redaction。
- nonce exhaustion采用两段可组合证据，不增加release API或状态：T02 crate-private
  `cfg(test)` unit直接把`TcpSealer`/`TcpOpener`的真实private counter置为
  `ff..ff`并调用实际AEAD owner；T03 crate-private `cfg(test)` one-shot
  cipher-boundary fault返回真实`AeadError::NonceExhausted`，随后必须经过production
  `FrameError`/`protocol_from_*`/lifecycle路径。不得公开test hook、增加release flag
  或直接安装预期terminal。
- runtime `OwnerRegistry`：supervisor child、connection task、buffer、permit、
  listener 和 forced-shutdown counters。T06直接测试其runtime语义；T07只在两个
  binary-private、production-used `run_with_registry` composition paths 注入同一个
  registry，不增加public binary observation seam。
- process harness：ephemeral ports、temporary config、readiness deadline、bounded
  stdout/stderr、child kill-on-drop；Unix listener从首次bind起使用reuse-address，
  Windows保持default，cleanup probe完成exact bind+listen且live same-policy owner
  必须阻止第二个listener。
- native socket probe：harness只用`aes-gcm`/`blake3` primitives独立构造current-time
  requests，对43个short prefixes与auth/type/time/length共47案比较批准的RST close
  class；不链接任何`ferrum2-*` crate。

protocol fake adapters与production adapters必须走同一泛型path；runtime paused
timer与production使用相同Tokio timeout code。mock只能观测capability，不得绕过
production validation/state transition。

### GitHub Actions required workflow contract

M0 required CI 固定为 `.github/workflows/m0.yml`。允许且仅允许
`pull_request`、push 到 `master`/`codex/integration/**` 和
`workflow_dispatch`；禁止 `pull_request_target` 及其他 trigger。

checkout 固定为
`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`
（v6.0.2），使用 `ref: ${{ github.sha }}`、`fetch-depth: 0`、
`clean: true`、`persist-credentials: false`。所有 `uses:` 引用必须是 reviewed
完整 40-hex commit SHA。顶层 permissions 只有 `contents: read`，未列权限为
`none`，job 不得提升。required job 不 cache、不依赖 cache hit、不
`continue-on-error`、不读取 `secrets.*`。

job ID 和 displayed name 必须精确相同，不能用 matrix suffix 改名：

| Required job | Runner | Timeout | Test IDs / exact command source |
|---|---|---:|---|
| `m0-host-quick` | `ubuntu-24.04` | 60 | M0-GATE-001；`workflow.toml` `[validation].quick` 三条命令 |
| `m0-security` | `ubuntu-24.04` | 60 | M0-WS-001/002、M0-CFG-003、M0-CRYPTO-001～004、M0-PROTO-001～009、M0-REPLAY-001～004、M0-DETECT-001、M0-BIND-001、M0-OBS-001/002；下方 evidence matrix 的每条命令、`cargo tree --workspace --locked`，以及 `cargo tree -p ferrum2-crypto --locked -e features -i aes`、`-i ghash`、`-i polyval`、`-i zeroize` 四条 focused commands |
| `m0-lifecycle` | `ubuntu-24.04` | 60 | M0-DETECT-003、M0-LIFE-001～005、M0-OBS-003；下方每条命令 |
| `m0-local-e2e` | `ubuntu-24.04` | 60 | M0-CFG-001/002、M0-CLI-001、M0-SOCKS-001/002、M0-ENDPOINT-001、M0-ADAPT-001/002、M0-E2E-001/002；下方每条命令 |
| `m0-integration-full` | `ubuntu-24.04` | 60 | M0-GATE-002、M0-SCOPE-001、M0-CI-001～006；`workflow.toml` `[validation].full` 与下方每条命令 |
| `m0-msrv` | `ubuntu-24.04` | 60 | M0-MSRV-001 两条 Rust 1.85.0 命令 |
| `m0-windows-msvc` | `windows-2022` | 60 | M0-PLAT-001、M0-DETECT-002；Compatibility matrix 全部命令 |
| `m0-linux-gnu` | `ubuntu-24.04` | 60 | M0-PLAT-002、M0-DETECT-002；Compatibility matrix 全部命令 |
| `m0-linux-musl` | `ubuntu-24.04` | 60 | M0-PLAT-003；Compatibility matrix 全部命令与 static assertions |
| `m0-interop-sing-box` | `ubuntu-24.04` | 60 | clean build、M0-INT-001/003 |
| `m0-interop-shadowsocks-rust` | `ubuntu-24.04` | 60 | clean build、M0-INT-002/004 |

`ubuntu-latest`、`windows-latest` 和所有 `*-latest` 禁止。所有 test commands
从 repository root 执行；harness package 名固定为 `ferrum2-m0-harness`。

每个 job 在生成文件前断言 checkout worktree clean 且
`git rev-parse HEAD == GITHUB_SHA`。platform/interop job 使用各自 GitHub-hosted
fresh VM，自行构建当前 commit binaries，不接收其他 job/run 的 ferrum2
artifact。每个 job 记录 run ID/attempt/job/SHA、`RUNNER_OS`/`RUNNER_ARCH`、
`ImageOS`、`ImageVersion`、OS/kernel、rustc/cargo/linker；CI status 必须链接
`Set up job` 的 exact `Included Software` URL。

GNU/musl provider evidence把compiler返回的absolute linker直接canonicalize；若返回
bare name则必须先用`command -v`解析，再验证executable并运行`--version`。Windows
MSVC provider evidence要求`link /?` exit仅为`0`或`1`，且合并输出包含Microsoft
linker/version banner；缺失/不可执行linker、其他exit或缺失banner均失败，合法help
exit 1不得污染step最终exit。M0-CFG-001与M0-REPLAY-001的list/run都必须以表中
full test name加libtest `--exact`运行并断言exact count 1。

M0 close evidence 只接受另行授权 push 后同一 run ID/attempt 的 11 个 job 对
exact integration `GITHUB_SHA` 全部 success。PR、manual、本机或 WSL2 result
若 SHA 不同只能诊断，不能替代。

## Acceptance-criteria evidence matrix

| Test ID | Spec criterion | Evidence/test | Level | Required job/command |
|---|---|---|---|---|
| M0-WS-001 | AC-01 | workspace members、crate DAG、core purity、`LocalEndpoint`/consuming reply ownership | contract/static | `cargo test -p ferrum2-m0-harness --test architecture --locked` |
| M0-WS-002 | AC-01/12 | ADR-0001/0009 production exact versions/features、ADR-0011/0015 exact harness-only dev-dependency/lock edges、ADR-0013两个binary exact Tokio dev-kind edges与production/test feature boundary、AES/GHASH/POLYVAL drop-zeroize resolved graph、110-tuple lock identity baseline、GPL metadata、publish false、unsafe forbid、license provenance | static/build | `cargo metadata --locked --format-version 1`；`cargo test -p ferrum2-m0-harness --test workspace_policy --locked`；`cargo tree --workspace --locked`；两个binary各自的Tokio normal/build与all feature trees；`cargo tree -p ferrum2-crypto --locked -e features -i aes`、`-i ghash`、`-i polyval`、`-i zeroize` |
| M0-MSRV-001 | AC-01/11 | Rust 1.85.0 resolved graph | build/test | `m0-msrv`：`cargo +1.85.0 check --workspace --all-targets --locked`；`cargo +1.85.0 test --workspace --locked` |
| M0-CFG-001 | AC-02 | 两 binary valid offline config；list/run均full-name exact 1 | process integration | list：`cargo test -p ferrum2-m0-harness --test config_cli --locked valid_client_and_server_configs_have_exact_offline_output -- --exact --list`；run：`cargo test -p ferrum2-m0-harness --test config_cli --locked valid_client_and_server_configs_have_exact_offline_output -- --exact` |
| M0-CFG-002 | AC-02 | offline path 零 listener/connector/task 副作用 | process integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked no_side_effects` |
| M0-CFG-003 | AC-02/12 | config negative matrix与 secret redaction | parameterized integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked invalid_matrix` |
| M0-CLI-001 | AC-02 | help/version、stdout/stderr、exit taxonomy | process integration | `cargo test -p ferrum2-m0-harness --test cli_contract --locked` |
| M0-CRYPTO-001 | AC-03 | BLAKE3 official derive-mode vectors | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked blake3` |
| M0-CRYPTO-002 | AC-03 | 两个固定McGrew/Viega GCM proposal cases 1/2 + corrupted-tag reject；submitter-supplied、historically hosted by NIST，非CAVP/NIST-authored validation vectors | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked aes128_gcm` |
| M0-CRYPTO-003 | AC-03/12 | SIP022 KDF output、key truncation与nonce-counter fixture | unit/KAT | `cargo test -p ferrum2-crypto --test sip022_vectors --locked` |
| M0-CRYPTO-004 | AC-03 | redacted secret、explicit-clear seam、entropy failure、salt collision、standalone counter与真实TCP AEAD owner nonce overflow | unit/negative | `cargo test -p ferrum2-crypto --test secret_entropy --locked`；`cargo test -p ferrum2-crypto --lib --locked tcp_owner_nonce_exhaustion` |
| M0-PROTO-001 | AC-04 | type/frame/address/padding/initial-payload bounds table | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked bounds` |
| M0-PROTO-002 | AC-04 | 每个 authenticated chunk bit flip与 truncation | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked auth` |
| M0-PROTO-003 | AC-04/05 | timestamp `±30`/`±31` | fake-clock unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked timestamp` |
| M0-PROTO-004 | AC-04 | S0-S3 reject 前 connector/forward/accepted/replay mutation 全零 | instrumented integration | `cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked` |
| M0-PROTO-005 | AC-04 | one encrypt/one per-RX decrypt reusable scratch；fixed usable-limit request、stable identity、无reserve/per-frame growth；独立bounded Session payload owner | safe buffer-observer + private unit | `cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked`；`cargo test -p ferrum2-shadowsocks --lib --locked flow_internal_contract` |
| M0-PROTO-006 | AC-04/12 | 有独立provenance的非官方request/response composite wire fixture | protocol KAT | `cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked` |
| M0-PROTO-007 | AC-04/07 | response pending时client upload与server request RX公平推进；server Session target/payload精确且flow不重复payload；current/pending cipher ownership与Send+Unpin闭合 | opaque-flow integration | `cargo test -p ferrum2-shadowsocks --test tcp_duplex --locked` |
| M0-PROTO-008 | AC-04/06 | fixed 43/59 single completed operation不变；全部post-fixed region支持one-byte/mixed fragmentation，mid-region EOF按closed table终止；zero-length subsequent frame不产生伪EOF | scripted transport integration | `cargo test -p ferrum2-shadowsocks --test tcp_fragmentation --locked` |
| M0-PROTO-009 | AC-04/06/08 | 0/1/16384/16385 write admission、single-scratch backpressure、normal repeat polls、client response-pending时16385结构性边界仍非fatal且nonce/I/O failure精确、server response-pending时auth/bounds/nonce/I/O failure精确、零abortive、exact terminal matrix、source redaction | poll-state integration + private cipher-boundary unit | `cargo test -p ferrum2-shadowsocks --test tcp_flow_contract --locked`；`cargo test -p ferrum2-shadowsocks --lib --locked flow_internal_contract` |
| M0-REPLAY-001 | AC-05 | invalid 不 poison；valid same salt first accept/second reject；list/run均full-name exact 1 | fake-state unit | list：`cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact_invalid_does_not_poison_then_duplicate_is_rejected -- --exact --list`；run：`cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact_invalid_does_not_poison_then_duplicate_is_rejected -- --exact` |
| M0-REPLAY-002 | AC-05 | 64-way duplicate 原子性 | concurrency | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked concurrent` |
| M0-REPLAY-003 | AC-05 | 59.999/60s retention与 wall rollback | fake-clock/state | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked retention` |
| M0-REPLAY-004 | AC-05 | capacity full fail closed，无 live eviction | state unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked capacity` |
| M0-DETECT-001 | AC-06 | every scripted Detection；single completed initial I/O；terminal-installed event早于恰好一次`mark_abortive`，mark失败不恢复 | instrumented transport/observer | `cargo test -p ferrum2-shadowsocks --test detection_prevention --locked` |
| M0-DETECT-002 | AC-06/11 | 43个valid fixed-region prefixes `n=0..42`及独立authenticated auth/type/time/zero-length rows共47案；typed branches分别ShortRead/Authentication/InvalidType/TimestampSkew/AddressBounds，native均reset非EOF且每案target accepts=0 | native process/socket + independent generator | `m0-windows-msvc` 与 `m0-linux-gnu` 各运行 `cargo test -p ferrum2-m0-harness --test detection_probe --locked` |
| M0-DETECT-003 | AC-06 | runtime `AbortiveClose`只在mark时设置zero linger；normal paths不设置 | runtime socket integration | `cargo test -p ferrum2-runtime --test abortive_close --locked` |
| M0-BIND-001 | AC-06 | response full request-salt equality，bad binding不 forward | protocol integration | `cargo test -p ferrum2-shadowsocks --test response_binding --locked` |
| M0-SOCKS-001 | AC-07 | connector在first-write前存local endpoint；success bytes为`05 00 00 01`+该IPv4/port；双向 bytes | unit/integration | `cargo test -p ferrum2-socks5 --locked`；`cargo test -p ferrum2-m0-harness --test local_e2e --locked success` |
| M0-SOCKS-002 | AC-07 | auth/cmd/domain/IPv6/malformed negative；每个 request-stage failure为`05 REP 00 01 00000000 0000` | unit/negative | `cargo test -p ferrum2-socks5 --test negative --locked` |
| M0-ENDPOINT-001 | AC-07 | client connector只收到configured SS server endpoint、request只编码application target；opaque connect-complete capability被一次消费；`local_addr`恰好查询一次；error/non-IPv4时零 SIP022 first-write，composition发精确general failure | cross-crate ordering | `cargo test -p ferrum2-runtime --test local_endpoint --locked`；`cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_target_and_request_target`；`cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_error_before_write`；`cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked client_open_phase_contract`；`cargo test -p ferrum2-socks5 --test negative --locked general_failure`；`cargo test -p ferrum2-client --locked local_endpoint_failure` |
| M0-ADAPT-001 | AC-06/07/08/09 | client TokioConnector/Transport/Framed机械delegation、initialized ReadBuf、Pending/call count、stored endpoint、fixed io::Error/source redaction；paused time以non-default durations和defaults证明configured connect与fresh configured request-first-write budgets、SOCKS success timing及timeout sole-owner drop；`test-util`只由ADR-0013 client dev edge启用；configured-SS Connect=`shadowsocks/failed`及全部terminal→Reason/stage/outcome mappings | binary unit integration | `cargo test -p ferrum2-client --locked adapter_contract`；`cargo test -p ferrum2-client --locked phase_deadline_contract` |
| M0-ADAPT-002 | AC-06/07/08/09 | server TokioTransport/Framed delegation；direct connect Pending/failure时零payload poll/forward；prefix partial writes只在nonzero progress重置idle，cancel/timeout/write-zero/error均保留精确count且不启动relay；paused-time capability只由ADR-0013 server dev edge启用；成功后Session.initial_payload恰好一次；direct Connect=`direct/failed`及全部terminal含Normal的observability mapping | binary unit integration | `cargo test -p ferrum2-server --locked adapter_contract`；`cargo test -p ferrum2-server --locked lifecycle_composition_contract` |
| M0-E2E-001 | AC-07 | 两真实 binary local echo + half-close + cleanup | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked success` |
| M0-E2E-002 | AC-07 | pre-success protocol failure与 post-success target refusal | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked failures` |
| M0-LIFE-001 | AC-08 | stalled writer停止 upstream read；buffer/permit cap | deterministic I/O | `cargo test -p ferrum2-runtime --test backpressure --locked` |
| M0-LIFE-002 | AC-08 | handshake/connect/idle timeout、cancel、listener failure；connect与request first-write budgets独立；relay failure保留每方向partial stats | fake-time integration | `cargo test -p ferrum2-runtime --test lifecycle --locked`；`cargo test -p ferrum2-client --locked phase_deadline_contract` |
| M0-LIFE-003 | AC-07/08 | one-way EOF后 reverse drain | integration | `cargo test -p ferrum2-runtime --test half_close --locked` |
| M0-LIFE-004 | AC-08 | graceful drain/deadline/forced termination | process/integration | `cargo test -p ferrum2-runtime --test shutdown --locked` |
| M0-LIFE-005 | AC-08 | 黑盒恰好100 cycles（success/auth reject/connect failure/cooperative cancel/forced termination各20）证明child wait、三类ports与temp cleanup；Unix真实流量后exact地址立即bind+listen，Windows保持default，live same-policy owner阻止第二listener；T06 direct counters及两个binary production-used registry composition tests先见live nonzero再回baseline，forced counter精确+1 | compositional deterministic repetition | `cargo test -p ferrum2-runtime --test lifecycle --locked`；`cargo test -p ferrum2-runtime --test shutdown --locked`；`cargo test -p ferrum2-client --locked lifecycle_composition_contract`；`cargo test -p ferrum2-server --locked lifecycle_composition_contract`；`cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked` |
| M0-OBS-001 | AC-09 | JSON schema + sentinel secret/destination scan | integration/snapshot | `cargo test -p ferrum2-observability --test tracing_contract --locked` |
| M0-OBS-002 | AC-09 | exposition names/types/labels/cardinality | integration/snapshot | `cargo test -p ferrum2-observability --test metrics_contract --locked` |
| M0-OBS-003 | AC-09 | runtime-owned `/metrics` permits/timeout/header/method bounds | runtime integration | `cargo test -p ferrum2-runtime --test metrics_endpoint --locked` |
| M0-INT-001 | AC-10/12 | ferrum client→sing-box server | required external E2E | `m0-interop-sing-box`：`cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_sing_box` |
| M0-INT-002 | AC-10/12 | ferrum client→shadowsocks-rust server | required external E2E | `m0-interop-shadowsocks-rust`：`cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_shadowsocks_rust` |
| M0-INT-003 | AC-10/12 | sing-box SOCKS client→ferrum server | required external E2E | `m0-interop-sing-box`：`cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact sing_box_client` |
| M0-INT-004 | AC-10/12 | shadowsocks-rust client→ferrum server | required external E2E | `m0-interop-shadowsocks-rust`：`cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact shadowsocks_rust_client` |
| M0-PLAT-001 | AC-11 | Windows MSVC release build + artifact config run | native build/run | `m0-windows-msvc` commands in Compatibility matrix |
| M0-PLAT-002 | AC-11 | Linux GNU release build + artifact config run | native build/run | `m0-linux-gnu` commands in Compatibility matrix |
| M0-PLAT-003 | AC-11 | Linux musl release build + artifact config run/link evidence | build/run | `m0-linux-musl` commands in Compatibility matrix |
| M0-GATE-001 | AC-11 | authoritative quick gate | repository gate | `m0-host-quick`：`workflow.toml` `[validation].quick` 每项 exit 0 |
| M0-GATE-002 | AC-11 | authoritative full gate | integration gate | `m0-integration-full`：`workflow.toml` `[validation].full` 每项 exit 0 |
| M0-CI-001 | AC-11 | 唯一 workflow path、exact trigger allowlist、拒绝 `pull_request_target` | static workflow policy | `m0-integration-full`：`cargo test -p ferrum2-m0-harness --test scope_audit --locked workflow_policy` |
| M0-CI-002 | AC-11 | 11 个 exact job ID/display name、runner mapping、每 job timeout 60 | static workflow policy | same `workflow_policy` command |
| M0-CI-003 | AC-11 | permissions、checkout full SHA/options、所有 `uses:` full SHA | static workflow policy | same `workflow_policy` command |
| M0-CI-004 | AC-11 | exact command allocation、current-SHA clean builds、no-cache dependency、无 cross-job ferrum artifact | static workflow policy | same `workflow_policy` command |
| M0-CI-005 | AC-10/11 | musl/GNU/native evidence、reference verification-before-execution、provider evidence、synthetic-no-secrets | static policy + job evidence | same `workflow_policy` command；对应 platform/interop job logs |
| M0-CI-006 | AC-11 | 一个 pushed exact integration SHA、单一 run ID/attempt 的 11-job close evidence | Team Lead/QA evidence review | `m0-integration-full` static policy；GitHub run/job URLs 与 exact SHA review |
| M0-SCOPE-001 | AC-12 | fixed-baseline diff/provenance/non-goal audit，唯一 CI allowlist path 为 `.github/workflows/m0.yml` | automated + Architect/QA review | `m0-integration-full`：`git merge-base --is-ancestor b41c6127b1834ebd97246451fd92bafea50cb205 HEAD`；`git diff --check b41c6127b1834ebd97246451fd92bafea50cb205...HEAD`；`cargo test -p ferrum2-m0-harness --test scope_audit --locked`；`cargo tree --workspace --locked` |

## Unit tests

### Workspace and config

- `architecture` 读取 `cargo metadata`，断言十个 members 精确、DAG 不含反向边；
  `core` 不含 Tokio/TOML/concrete package。
- `workspace_policy` 断言 production direct versions/features 与 ADR-0001 经
  ADR-0009 部分取代后的 baseline exact 相等；ADR-0011经ADR-0015部分取代后 harness
  direct dev dependencies必须精确为
  `aes-gcm`、`blake3`、`hex`、`serde_json`、`socket2`、`tempfile`，其中
  `aes-gcm`、`blake3`和`socket2`只用workspace inheritance，且没有任何
  `ferrum2-*` dependency。所有 project package 继承
  license/publish/lints、`Cargo.lock` tracked。它还从 locked Cargo metadata
  断言 `ferrum2-crypto` 的 exact/no-default/normal/unrenamed/unconditional
  `aes`/`ghash` anchors 与 `aes-gcm` transitive edges 解析到相同且唯一的 exact
  registry package IDs，并断言 resolved-node exact feature sets：
  `aes-gcm={aes,bytes,zeroize}`、`aes={zeroize}`、
  `ghash={zeroize}`、`polyval={hazmat,zeroize}`、
  `zeroize={aarch64,alloc,derive,zeroize_derive}`。这会拒绝
  `aes-gcm/hazmat`/`aes/hazmat`，同时保留 required `polyval/hazmat`。
  `cargo tree` 中由 upstream edges 显示的空 `aes/default`/`polyval/default`
  不被误报为额外 node feature；四条 focused trees 必须同时显示这两个空
  default edges、`polyval/hazmat` 与 induced `zeroize/aarch64`，作为
  metadata node sets 之外的 exact edge evidence。
- ADR-0013 exception 后，两个binary manifests都必须保留exact normal
  `tokio.workspace = true`并各自只新增一个dev-kind workspace-inherited
  `test-util` declaration；root/normal declarations不得出现`test-util`。locked
  metadata必须分别显示normal/dev kinds与同一Tokio identity；排除dev edges的两个
  production trees不得出现`tokio feature "test-util"`，包含dev edges的两个test
  trees必须各出现一次。manifest LF/CRLF positive fixtures verdict相同，并拒绝
  missing-one-side、extra/missing feature、normal/root移动、`full`、version/default/
  source/path/git/rename/optional/target/duplicate-table mutations。
- `workspace_policy` 内嵌 integration checkpoint `999d4f9`、
  lock blob `ab04f6d` 的完整 110 个 `(name,version,source,checksum)` identity
  tuples；candidate lock parser 的 sorted result 必须 exact 相等。lock diff只准
  `ferrum2-m0-harness` dependency list增加
  `"aes-gcm"`/`"blake3"`/`"socket2"`，package count、identity tuples和
  resolved production feature sets不变。root/member manifest helpers 与 lock
  parser 对同一 LF/CRLF positive fixtures 以及
  bare CR、addition/removal/version/source/checksum/feature/dependency-edge mutation
  negative fixtures产生相同 verdict。完整 `cargo tree` 做人工 provenance/license sign-off，
  不以“能编译”代替。
- 上述exact declarations、110 tuples与feature sets是当前profile的基线。经
  ADR-0016执行前amendment批准替换test-only edge或policy representation时，测试
  必须精确比较新profile，并同时证明production/release dependency tree、crypto
  zeroize feature graph、version/source/checksum/license和有效coverage未改变。
- config table覆盖每个 missing/unknown field、上下界/界外值、port 0、non-loopback
  metrics、internal endpoint equality、method/base64/key/file-size/UTF-8。

### Crypto and protocol

- primitive vector测试逐 case显示 vector ID，不在失败输出显示 runtime secret。
- crypto KDF/nonce fixture逐字段断言full 32-byte BLAKE3 output、used first
  16 bytes、zero nonce、carry和overflow。
- protocol composite fixture由`ferrum2-shadowsocks`测试逐字段断言每个nonce、
  plaintext/ciphertext/tag与完整request/response first-write wire bytes；该fixture
  明确不是官方SIP022 KAT。
- primitive input选择固定为ADR-0004的BLAKE3 `input_len=0,1,1024` rows和
  ADR-0008的McGrew/Viega GCM proposal test cases 1/2；不得由Engineer替换为
  “任意几个能过的vector”。两个AES numeric cases与corrupted-tag reject不变。
- composite input、generator path和provenance fields完全固定为ADR-0004；test
  runtime只读取并断言committed bytes，不更新fixture。
- nonce测试从 zero开始、跨 byte carry、最终 overflow；overflow前后不输出/接受
  重复 nonce。
- `local_endpoint`用可脚本化socket inspector覆盖成功、lookup error与IPv6结果：
  每案恰好一次查询；后两案不返回stream。`connector_error_before_write`断言这些
  connect errors使`TransportIo` completed write count保持0；SOCKS与client composition tests
  再断言最终reply恰好为`05 01 00 01 00000000 0000`且只发送一次。
- `connector_target_and_request_target`使用互不相同的configured SS server与
  application target，断言recording connector只收到前者，而authenticated request
  解码只得到后者；不得通过Tokio adapter改写二者。
- `client_open_phase_contract`只用controlled connector/transport futures证明
  connect-complete capability与request-first-write可独立Pending/complete、
  capability被consuming一次、cancel/drop释放sole transport owner且没有内部spawn；
  该T03 test不使用Tokio paused time或断言configured duration数值。
- protocol negative table至少包括：每个 chunk tag bit flip、0..完整长度的关键
  truncation points、type 0/1反转、ATYP、port 0、padding 901、padding overrun、
  empty padding+payload、length arithmetic、trailing/under-consumed header、
  response binding mismatch。
- `tcp_duplex`在response fixed-read保持`Pending`时推进至少两个client request
  frames；server侧在first response保持`Pending`时消费至少一个subsequent request
  frame。always-ready one-byte transport下，每个outer poll最多一次underlying
  operation，另一logical direction在固定poll bound内进展。server accept断言
  `Session.target`/`initial_payload`精确、flow首个plaintext read不重复payload。
  test-only compile assertions证明production-shaped client/server flows为
  `Send + Unpin`，并证明pending response capability只创建一次cipher owner。
- `tcp_fragmentation`保持43/59-byte fixed region一个completed read；request
  variable、response first payload、subsequent length/payload分别用one-byte与mixed
  fragments成功。initial/mid-frame EOF、bit flip、type/time/length/binding分别映射
  Detection或Protocol table，且terminal后read/write count不再增加。
- allocation observer在handshake、minimum、maximum及至少32个subsequent frames后
  断言每flow一个encrypt、每receive direction一个decrypt fixed request，storage
  identity不变且无reserve/growth；不得用requested read length代替allocation
  evidence。initial payload另为auth/semantics后创建的一个`Session` Bytes，
  `0..=65526`边界与drop/forward ownership单独断言。公开`BufferObserver`只保留
  role、requested usable limit和opaque identity；capacity由crate-private unit
  直接观察，不增加hot-path callback。
- `tcp_flow_contract`表驱动断言：empty source为`Ok(0)`且零I/O/nonce/response；
  1与16384完整admit；16385只admit/return 16384；scratch未drain时第二个source
  `Pending`且不被复制，drain后才admit当前source，不依赖重交旧buffer。zero-length
  read零I/O；RX EOF后重复read仍EOF；TX shutdown幂等、之后flush/shutdown成功且
  零I/O；RX仍open时nonempty write-after-shutdown固定为`Transport(Write)`；
  双向已关闭的`Normal`则read/write=`Ok(0)`、flush/shutdown成功、terminal不变且
  零I/O。server
  response-pending empty flush零I/O，shutdown零header且error精确映射
  `Transport(Shutdown)`，不得伪装为Detection。
- 同一`tcp_flow_contract`穷尽`ProtocolReason`、`TransportPhase`与`FlowTerminal`
  table，逐项证明abortive=0、fatal后所有方向返回同一error且counts冻结；transport
  source sentinel不出现在Debug/Display/source。状态组合必须显式覆盖client response
  first-envelope仍pending时subsequent request-TX的`16385 -> admit 16384`
  非fatal结构性边界及nonce/I/O failure；ADR-0010的admission cap使client TX
  `FrameBounds`不可达，不得为测试注入该terminal。server response first-envelope仍
  pending时subsequent request-RX继续覆盖auth/bounds/nonce/I/O failure；fatal项仍为
  对应Protocol/Transport、abortive=0，不得改类为Detection。
- `flow_internal_contract`只在crate `cfg(test)` build存在：client/server flow的
  private one-shot cipher-boundary fault必须返回`AeadError::NonceExhausted`并经过
  现有frame/protocol/lifecycle映射；不得直接调用terminal安装函数。它还直接读取
  private scratch capacity，证明minimum/maximum与32帧后没有growth。release build
  的public methods、fields、trait callbacks与布局不得因此增加。
- T02的2-test owner evidence与T03的4-test mapping/capacity evidence必须合入同一
  final integration SHA并由Architect/QA组合复核；任一分支单独通过都不构成完整
  nonce-exhaustion证据。
- `tcp_fragmentation`在非空destination下认证一个zero-length subsequent payload，
  断言nonce/state推进、outer poll self-wake/Pending且不返回`Ok(0)`；后续合法非空
  frame仍被交付，只有真正frame-boundary transport EOF才产生read EOF。
- detection test分别从client response initial-read与server response first-write
  注入failure；pre-flow request initial read/write覆盖同一matrix。
  `FlowObserver`与transport recorder断言terminal-installed sequence严格早于
  `mark_abortive`，合计恰好一次且mark failure不恢复。post-first-envelope
  protocol/transport fatal、clean EOF、half-close与cancel均为0次abortive。

### Replay and ordering

- timestamp table：`now-31` reject、`now-30` accept、`now` accept、
  `now+30` accept、`now+31` reject。
- invalid auth/type/time/address/padding 不插入；随后同 salt合法 request必须能成为
  first success。
- 64 tasks barrier同步提交同一合法 header，结果精确 `1 accepted + 63 replay`。
- monotonic `59.999s` 不 purge，`60.000s` 可 purge；wall clock任意回退不改变。
- capacity装满 live entries后新 salt返回 `ReplayCapacity`，原 entries仍可检测。
- `RecordingConnector`/metrics/forward recorder断言完整 semantic success之前全零。

### Workflow policy

M0-CI-001～006 复用 M0-T08 已有 ownership
`tests/m0-harness/tests/scope_audit.rs`，不得为 YAML parsing 新增 Cargo
dependency。`workflow_policy` 对唯一 workflow 做静态 contract audit：

- exact path、trigger allowlist 与 `pull_request_target`/其他 trigger 拒绝；
- exact job ID/display name、runner、字面量数值 timeout、无
  `continue-on-error`；
- top-level permissions、无 job elevation、checkout full SHA/options、所有
  `uses:` full SHA；
- job-to-command mapping、无 cache、platform/interop current-SHA self-build、
  无 cross-job ferrum artifact；
- musl version/static checks、GNU native smoke/detection、provider evidence、
  reference verify-before-run 和无 `secrets.*`；
- close evidence 必须关联 one pushed exact integration SHA、one run ID/attempt。

static test 不能伪造远程 run；M0-CI-006 还需要 Team Lead/QA 对 GitHub run/job URL、
run ID/attempt 和 `GITHUB_SHA` 做 evidence review。

## Integration and interoperability tests

### Local product path

`adapter_contract` unit integrations直接实例化binary-local production adapters：

- client记录connector/transport/framed每次poll、Pending、read/write/flush/shutdown、
  endpoint与abortive delegation；`ReadBuf`只推进initialized bytes。
- client `phase_deadline_contract`使用paused time分别卡住configured-server connect和
  request contiguous first-write：至少一组non-default validated durations证明没有
  硬编码，另以defaults证明10秒connect timeout映射`ConnectTimeout`、connect成功后
  fresh 5秒才产生`Reason::HandshakeTimeout`；慢connect不侵占后者，SOCKS success
  只在first-write完成后发生，timeout/cancel后无detached task且abortive为0。
- server recording direct connector在Pending/failure时断言
  `Session.initial_payload`零poll/forward；成功后即使target partial writes也按原
  byte sequence完整恰好一次写完，再开始ordinary relay，`ServerFlow`不重复。
  prefix table覆盖empty、partial-progress、partial-then-error、stalled timeout、
  cancellation与write-zero；只有successful nonzero write重置idle，每个失败保留
  exact prefix count且relay poll count为0。
- 两边对每个typed terminal断言ADR-0010 fixed `io::ErrorKind`、`get_ref()=None`、
  standard message与source sentinel零匹配。表驱动穷尽每个`DetectionReason`、
  `ProtocolReason`、`TransportPhase`、`ConnectErrorKind`与`Normal`到exact
  `Reason`/stage/outcome的映射；client configured-SS Connect必须是
  `shadowsocks/failed`，server direct-target Connect必须是`direct/failed`，
  Normal必须是`relay/completed/no reason`。
  源码/Architect review再确认adapter没有frame/cipher/replay/binding/allocation/
  terminal policy。

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

`ferrum2-m0-harness`不链接任何concrete ferrum2 crate。`m0-local-e2e`先运行
`cargo build --workspace --bins --locked`，harness从metadata target directory定位
当前platform binaries；artifact缺失即失败。

### External interoperability

四个 M0-INT tests默认 `#[ignore]` 只为防止 host quick 隐式依赖外部 binary；required
jobs必须用 `--ignored --exact` 显式执行。test读取 `tests/interop/versions.toml`，
要求 runner provision的 binary path存在且 version/artifact SHA-256完全匹配。
缺 env/path、下载失败、checksum/version mismatch、readiness timeout、child crash
或 case timeout直接失败；不得 `return Ok(())`、fallback latest 或把 ignored 状态
报告为 pass。

`m0-interop-sing-box` 与 `m0-interop-shadowsocks-rust` 分别在自己的 fresh
`ubuntu-24.04` VM 断言 current `GITHUB_SHA`，运行
`cargo build --workspace --bins --locked`，不得使用 T07、另一 job 或先前 run 的
artifact。reference archive 下载到 runner temp，必须先核实 ADR-0006 固定的
size/SHA-256/license record，再 safe extract，并在任何 interop case 前核实固定
version output；unexpected archive entry同样失败。配置只使用
`AAECAwQFBgcICQoLDA0ODw==` synthetic PSK，不读取 repository secrets。

每个 case验证 TCP-only AES-128、pre-FIN双向payload、ordered clean-EOF
convergence、reference进程清理：

1. application client写固定16386-byte forward payload；target不等待EOF，读取
   exact length并逐byte比较。
2. target写入distinct fixed 16386-byte reverse payload；application client读取
   exact length并逐byte比较。
3. 仅在两次equality均成功后application client `Shutdown::Write`；target在I/O
   deadline内观察clean `Ok(0)`后成功`Shutdown::Write`；application client随后
   在deadline内观察clean `Ok(0)`。

truncation、extra byte、premature EOF、reset/error、mismatch或timeout任一失败。
mutation
evidence必须杀死equality前FIN、target未见clean `Ok(0)`、target write shutdown
失败、client未见clean `Ok(0)`与expected reverse后extra byte。该external
sequence只证明双向
wire/data与ordered clean-EOF convergence；它不证明reference在第一次FIN后仍保持
reverse leg，也不证明target FIN导致client EOF。peer FIN后新产生reverse bytes
继续由同一最终SHA的
M0-E2E-001和M0-LIFE-003独立blocking，四项external PASS不得替代。

这是当前external selected profile。可替换payload字面值、test/helper布局或记录
机制，但每方向payload必须distinct且不少于16386 bytes，必须在FIN前逐byte比较，
四个reference/direction与ordered clean-EOF仍分别required。

case timeout 60 秒，readiness 10 秒，I/O 10秒，stdout/stderr各 cap 256 KiB；
超限截断并标记，kill-on-drop。只保存 sanitized diagnostics。

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
- native detection probe以primitive-only generator生成一个valid current-time
  request的43个fixed-region prefixes `n=0..42`；auth row只在valid packet生成后翻转
  fixed ciphertext/tag一位；type row独立seal `type=1`；time row至少stale 120秒；
  length row seal current-time type 0/declared length 0并追加nonce 1 valid empty tag。
  direct typed evidence分别必须是ShortRead/Authentication/InvalidType/TimestampSkew/
  AddressBounds。每个47案都观察`ConnectionReset`而非EOF，并在该案后立即断言
  target accept count 0。Windows与Linux GNU为 M0 blocking；musl完整 close matrix留
  M3。
- ADR-0016允许调整47-row probe的process/helper组织，但不得减少43个prefix及
  auth/type/time/length rows，不得调用production encoder/parser形成circular
  oracle，且每row仍须native、reset-not-EOF、target accepts为0。
- fixture checksum/provenance在测试前验证；production code不能包含 fixture-only
  key、scripted RNG 或 bypass。

## Concurrency, race, and soak tests

- replay 64-way barrier test重复至少 20轮，不能出现0或>1 accepted。
- stalled writer使用受控容量 transport：达到 buffer cap后 upstream read count不再
  增长，恢复 writer后无丢字节。
- lifecycle用 paused/fake time，不使用长 wall sleep；T06 direct tests在固定step后
  真实 owner registry回零且socket可重绑。binary-private production-used
  `run_with_registry` tests必须先观察active child/task/buffer/permit/listener的
  nonzero witness，再等待supervisor/JoinSet完成并回baseline；cumulative
  `forced_shutdowns`断言精确`+1`。
- `lifecycle_cycles`恰好100轮，success、auth reject、connect failure、cooperative
  cancel和forced termination各20。每个child timed-waited，proxy/metrics/target
  原地址逐一重绑，temporary path不存在，harness child registry回起点。黑盒结果
  不得声称直接观察进程内counter。
- runtime relay failure tests对I/O、idle和cancel逐方向断言failure前successful
  application writes保留在`RelayStats`；read-ahead/pending/write-zero不计数。
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

四个 platform config fixtures 固定为：

```text
tests/platform/config/client-valid.toml
tests/platform/config/client-invalid-key-length.toml
tests/platform/config/server-valid.toml
tests/platform/config/server-invalid-key-length.toml
```

valid command必须 exit 0，invalid-key-length command必须 exit 2；四次都证明未创建
listener。所有 config 只含 synthetic PSK。

`m0-windows-msvc` 在 `windows-2022`：

```text
rustup toolchain install 1.97.1 --profile minimal
rustup target add --toolchain 1.97.1 x86_64-pc-windows-msvc
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-pc-windows-msvc
target\x86_64-pc-windows-msvc\release\ferrum2-client.exe --config tests\platform\config\client-valid.toml --check-config
target\x86_64-pc-windows-msvc\release\ferrum2-client.exe --config tests\platform\config\client-invalid-key-length.toml --check-config
target\x86_64-pc-windows-msvc\release\ferrum2-server.exe --config tests\platform\config\server-valid.toml --check-config
target\x86_64-pc-windows-msvc\release\ferrum2-server.exe --config tests\platform\config\server-invalid-key-length.toml --check-config
cargo test -p ferrum2-m0-harness --test detection_probe --locked
```

`m0-linux-gnu` 在 `ubuntu-24.04`：

```text
rustup toolchain install 1.97.1 --profile minimal
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-gnu
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-gnu
target/x86_64-unknown-linux-gnu/release/ferrum2-client --config tests/platform/config/client-valid.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-client --config tests/platform/config/client-invalid-key-length.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-server --config tests/platform/config/server-valid.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-server --config tests/platform/config/server-invalid-key-length.toml --check-config
cargo test -p ferrum2-m0-harness --test detection_probe --locked
```

两个 GNU artifacts 必须在该 VM 原生实际运行；另以 `file`、`readelf` 记录 ELF
interpreter、`DT_NEEDED` 和 required `GLIBC_*` symbols。

`m0-linux-musl` 在 `ubuntu-24.04`：

```text
sudo apt-get update
sudo apt-get install --yes --no-install-recommends musl=1.2.4-2 musl-dev=1.2.4-2 musl-tools=1.2.4-2
dpkg-query -W musl musl-dev musl-tools
rustup toolchain install 1.97.1 --profile minimal
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-musl
target/x86_64-unknown-linux-musl/release/ferrum2-client --config tests/platform/config/client-valid.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-client --config tests/platform/config/client-invalid-key-length.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-server --config tests/platform/config/server-valid.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-server --config tests/platform/config/server-invalid-key-length.toml --check-config
file target/x86_64-unknown-linux-musl/release/ferrum2-client target/x86_64-unknown-linux-musl/release/ferrum2-server
readelf -hW target/x86_64-unknown-linux-musl/release/ferrum2-client
readelf -lW target/x86_64-unknown-linux-musl/release/ferrum2-client
readelf -dW target/x86_64-unknown-linux-musl/release/ferrum2-client
readelf -hW target/x86_64-unknown-linux-musl/release/ferrum2-server
readelf -lW target/x86_64-unknown-linux-musl/release/ferrum2-server
readelf -dW target/x86_64-unknown-linux-musl/release/ferrum2-server
```

Ubuntu package index update不得改变上述 exact package version；version 不可用
即 FAIL。两个 artifacts 都必须被 `file` 识别为
static/static-pie，且 `readelf -lW/-dW` 不得出现 `PT_INTERP` 或
`DT_NEEDED`。只打印工具输出而不做 assertion、只 build 不原生运行均失败。

| Test | Triple / runner | Extra evidence |
|---|---|---|
| M0-PLAT-001 | `x86_64-pc-windows-msvc` / `windows-2022` | Windows kernel/build、PE artifact SHA-256、rustc/cargo/VS 2022 `cl`/`link`、valid 0/invalid 2、无 listener；M0-DETECT-002 PASS |
| M0-PLAT-002 | `x86_64-unknown-linux-gnu` / `ubuntu-24.04` | `uname`/kernel、glibc/`cc`/`ld`、ELF interpreter/`DT_NEEDED`/required `GLIBC_*` symbols、artifact SHA-256、四次 native run；M0-DETECT-002 PASS |
| M0-PLAT-003 | `x86_64-unknown-linux-musl` / `ubuntu-24.04` + exact `musl-tools=1.2.4-2` | package/linker versions、`file`/`readelf` no-`PT_INTERP`/no-`DT_NEEDED` assertions、artifact SHA-256、四次 native run |

每个 artifact对两个 binaries各运行 valid/invalid，共四次。只 `cargo check`、只构建
library、只看 artifact文件存在均失败。

每个 platform job 记录 `ImageOS`、`ImageVersion`，并在 CI status 链接该 job
`Set up job` 的 exact `Included Software` URL；另记录 OS/kernel、
`rustc -Vv`、Cargo、实际 compiler/linker、BLAKE3 backend 和 artifact SHA-256。
GitHub-hosted VM 不提供本项目可固定的 OCI image digest；这些 provider-native
字段只批准为 M0 smoke evidence，不是 M3 完整平台 qualification。

MSRV 在 `ubuntu-24.04` 先执行
`rustup toolchain install 1.85.0 --profile minimal`，再执行 M0-MSRV-001；
1.97.1 current build不能替代。BLAKE3 build backend/C compiler在三个 target
evidence中记录。

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
  `tests/fixtures/sip022/**`。BLAKE3 commit/file hash/cases与composite exact
  inputs/generator path由ADR-0004固定；McGrew/Viega proposal archive/entry/spec/
  IPR hashes、test cases 1/2、submitter-source classification、`NOASSERTION`及rights
  evidence由ADR-0008固定。每组provenance metadata记录source、license-or-rights
  review、SHA-256和expected interpretation。
- bytes、numeric result、pin与expected interpretation不变的来源/作者/URL/hash
  转录或rights classification勘误按ADR-0016作为evidence amendment处理；必须保留
  superseded记录、取得Architect/QA复核并重跑provenance/fixture gates。改变
  bytes/result/pin或license/distribution conclusion仍不是勘误。
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

唯一 out-of-band 分类是用户明确授权的既有 skill optimization commit
`d1ef4bcfb081a89c5da1185dcb7c57606f8ec77e` 中 23 个 exact control-plane
paths。`scope_audit` 仍枚举完整 baseline diff，但仅在以下条件全部成立时跳过这些
路径的 M0 内容/provenance scan：`d1ef4bcf` 的精确 parent 与完整 commit path set
匹配；它是 `HEAD` ancestor；23 个路径逐项精确匹配且 `HEAD` blob 与
`d1ef4bcf` blob 相同。任何 omission、extra path、rename、descendant、
suffix/extension、same-directory sibling、wildcard/prefix 或 blob drift 都必须
fail closed。该分类不授权修改这些文件，也不排除 `.codex/agents/qa.toml`、
`docs/ci-status.md`、`docs/roadmap.md` 或 M0-T07/T08 ticket 的正常内容扫描。

`scope_audit` 必须自动拒绝：不在 M0 tickets/control-doc allowlist 的路径、
`target/`/coverage/profile/pcap/log/result、可执行或压缩的 external artifact、
缺 `PROVENANCE.toml`/source/license-or-rights review/SHA-256/expected
interpretation 的 fixture，
以及 production tree 中 fixture-only key/scripted RNG/bypass。唯一批准的
`.github` 路径是 M0-T08 ownership 下的 `.github/workflows/m0.yml`；其他
workflow/action/config 一律拒绝。随后 Architect 与 QA 对
`git diff --name-status --find-renames
b41c6127b1834ebd97246451fd92bafea50cb205...HEAD` 和
`cargo tree --workspace --locked` 明确签署以下 checklist：

- 所有变更落在批准的 M0 product/control ownership，未实现 AES-256、ChaCha、UDP、
  public UDP inbound、domain/DNS、multi-user/EIH、routing/management 或性能范围；
- out-of-band skill snapshot 只包含上述 exact 23 paths，commit lineage/path set/blob
  identity 完全匹配，且没有 wildcard、rename、额外路径或后续内容变更；
- 无 real secret、production endpoint、外部 binary、generated result或未审 fixture；
- production dependency/member/method surface与 ADR-0001 经 ADR-0009 部分取代后
  的 baseline相等；ADR-0011经ADR-0015部分取代后只允许harness两个test-only
  primitive edges（`aes-gcm`/`blake3`）加一个rebind-evidence edge（`socket2`）
  及对应唯一lock hunk；ADR-0013只允许两个binary dev-only Tokio `test-util`
  declarations且不产生lock hunk，production trees不含该feature；110 package
  identities/resolved crypto feature sets不变；`aes 0.9.1`/
  `ghash 0.6.0`仅为已锁定 permissive feature anchors，
  version/source/checksum 不变，新增 direct surface 有license/provenance；
- T02/T03 fixtures与两个 reference pins的来源、hash、license-or-rights review和
  非分发策略完整。

以上dependency allowlist是当前selected profile。任何ADR-0016 substitution必须在
执行前写入本节与对应ticket，并由scope audit精确验证amended profile；不存在通配
allowlist，且不得降低production graph、zeroize、license、MSRV或platform证据。

## Exit conditions and known gaps

M0 test gate通过需要：

1. 表中 M0-WS～M0-CI～M0-SCOPE 每个 required ID有同一 integrated commit 的
   PASS evidence。
2. `workflow.toml` quick/full所有命令实际运行且 exit 0。
3. 四项 interop与三项 platform smoke无 skip/缺失。
4. 另行授权 push 后，同一 GitHub Actions run ID/attempt 的 11 个固定 job 对
   exact integration `GITHUB_SHA` 全部 success；provider-native runner evidence
   与 Included Software links 完整。
5. Architect与QA复核 spec符合性、security ordering、ownership和 evidence。
6. 未发现 committed external/generated artifact、real secret或M0 non-goal。

已知但明确延期：

- AES-256/ChaCha和完整地址/TCP matrix：M1。
- UDP/replay window/session limits：M2。
- 全平台长期 lifecycle和最终 operator stability：M3。
- throughput、10,000 idle与长期资源阈值：M4。

T01～T08 reviewed candidates已在exact `51fb7327`汇合并通过local integration、
Architect与QA gates；其hosted run `30301746374`为2/11 success、9/11 failure。
当前缺口是ADR-0015/T07 Unix listener restart、T08 evidence-script修复、修复后
新exact SHA的全部local/Architect/QA再资格，以及一个separately authorized
11/11 hosted run。旧run的两个interop success不能拼接或豁免这些required future
evidence。required job 启动后
setup/network/package/reference/command/timeout/evidence 失败是 FAIL；workflow、
未授权 push、provider 或 job 未产生结果是 BLOCKED。missing/skipped/cancelled/
neutral 都不会转换为 waiver 或 PASS。
