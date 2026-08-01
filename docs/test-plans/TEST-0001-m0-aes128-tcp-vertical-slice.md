# TEST-0001: M0 AES-128-GCM TCP 安全纵切

- **Status:** Approved
- **ADR-0010 amendment:** Approved
- **ADR-0011/0012 amendments:** Approved
- **ADR-0013 amendment:** Approved
- **ADR-0014 amendment:** Approved
- **ADR-0015 amendment:** Approved
- **ADR-0016 amendment:** Approved
- **ADR-0017 amendment:** Approved
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

ADR-0017 的 hosted profile不再使用name substring、`--list | grep`或test-count
作为required evidence。`quality`运行完整Cargo targets；focused本地诊断可以使用
full-name `--exact`，但不进入release command allocation，也不能替代完整target。

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

initial profile有四个job definitions、六个rendered results：

| Definition | Runner / cells | Test IDs / command source |
|---|---|---|
| `quality` | `ubuntu-24.04` | 先build workspace bins，再执行M0-GATE-002及AC-01～09；`workflow.toml` full四条命令只运行一次 |
| `msrv` | `ubuntu-24.04` | M0-MSRV-001：Rust 1.85.0 check全部targets并实际运行workspace tests |
| `platform` | `windows-2022` Windows MSVC；`ubuntu-24.04` GNU/musl，`fail-fast: false` | M0-PLAT-001～003、两平台M0-DETECT-002及Compatibility matrix |
| `interop` | `ubuntu-24.04` | Cargo-managed `test = false` qualification binary；M0-INT-001～004固定四行summary，4/4才exit 0 |

job name/count与exact timeout不是永久不变量；每个job仍设置bounded numeric
timeout。`ubuntu-latest`、`windows-latest`和所有`*-latest`禁止。所有commands
从repository root执行。

每个job在生成文件前断言checkout worktree clean且
`git rev-parse HEAD == GITHUB_SHA`，在自己的fresh VM从current SHA构建所需
ferrum2 artifacts，不接收其他job/run的ferrum artifact。每个job记录run
ID/attempt/job/SHA、runner label、`RUNNER_OS`/`RUNNER_ARCH`、`ImageOS`、
`ImageVersion`、OS/kernel和rustc/cargo；platform另记录artifact hash与适用的
native/linkage证据。

release build和native artifact execution证明linker可用；不执行
`link.exe /?`、GNU/musl linker-help/canonicalization或backend probe。
`quality`运行完整targets，不使用substring filter、list/count guard。

qualification binary必须出现在Cargo metadata且manifest设置`test = false`，
受workspace unsafe/lint/dependency/license/lock policy约束。quick/full、
all-features和all-targets可以编译/lint它，但不得执行entry、external cases或
OS/process helper tests；本机只运行无socket/process/network的pure state tests。
interop job以Cargo显式构建并运行entry；entry可用固定参数调用`git`读取checkout
identity，随后在任何network/socket I/O或reference/ferrum child前验证GitHub
Linux、clean checkout与exact SHA。driver分别provision两个references；一个失败时
其两案以同一setup root报告FAIL而不声称执行，另一个reference的可运行cases仍
尝试。单案失败、timeout、panic或cleanup failure后继续其余案，最终固定报告
M0-INT-001～004；summary只含case ID、PASS/FAIL和可选canonical root，非4/4失败。

M0 close evidence只接受另行授权push后同一run ID/attempt的六个预期rendered
results对exact integration `GITHUB_SHA`全部success，且完整workflow conclusion
为success。missing/skipped/cancelled/neutral/timed-out或无法归属均非PASS。
PR、manual、本机或WSL2 result若SHA不同只能诊断，不能替代。

## Acceptance-criteria evidence matrix

下表最后一列若明确写出`quality`、`msrv`、`platform/*`或`interop`，表示selected
hosted allocation；其余Cargo命令标识由`quality`/full覆盖的完整target，不是要求
每行单独重复执行。required allocation不使用substring filter、list/count guard；
需要聚焦诊断时只可使用完整test name加`--exact`，且不能替代完整target。

| Test ID | Spec criterion | Evidence/test | Level | Hosted allocation / complete target |
|---|---|---|---|---|
| M0-WS-001 | AC-01 | workspace members、crate DAG、core purity、`LocalEndpoint`/consuming reply ownership | contract/static | `cargo test -p ferrum2-m0-harness --test architecture --locked` |
| M0-WS-002 | AC-01/12 | ADR-0001/0009 production exact versions/features、ADR-0011/0015 exact harness-only dev-dependency/lock edges、ADR-0013两个binary exact Tokio dev-kind edges与production/test feature boundary、AES/GHASH/POLYVAL drop-zeroize resolved graph、110-tuple lock identity baseline、GPL metadata、publish false、unsafe forbid、license provenance | static/build | `cargo metadata --locked --format-version 1`；`cargo test -p ferrum2-m0-harness --test workspace_policy --locked`；`cargo tree --workspace --locked`；两个binary各自的Tokio normal/build与all feature trees；`cargo tree -p ferrum2-crypto --locked -e features -i aes`、`-i ghash`、`-i polyval`、`-i zeroize` |
| M0-MSRV-001 | AC-01/11 | Rust 1.85.0 resolved graph与runtime tests | build/test | `msrv`：`cargo +1.85.0 check --workspace --all-targets --locked`；`cargo +1.85.0 test --workspace --locked` |
| M0-CFG-001 | AC-02 | 两binary valid offline config | process integration | `quality`完整执行`cargo test -p ferrum2-m0-harness --test config_cli --locked`；focused诊断可使用full-name `--exact`但不是required allocation |
| M0-CFG-002 | AC-02 | offline path 零 listener/connector/task 副作用 | process integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked` |
| M0-CFG-003 | AC-02/12 | config negative matrix与 secret redaction | parameterized integration | `cargo test -p ferrum2-m0-harness --test config_cli --locked` |
| M0-CLI-001 | AC-02 | help/version、stdout/stderr、exit taxonomy | process integration | `cargo test -p ferrum2-m0-harness --test cli_contract --locked` |
| M0-CRYPTO-001 | AC-03 | BLAKE3 official derive-mode vectors | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked` |
| M0-CRYPTO-002 | AC-03 | 两个固定McGrew/Viega GCM proposal cases 1/2 + corrupted-tag reject；submitter-supplied、historically hosted by NIST，非CAVP/NIST-authored validation vectors | unit/KAT | `cargo test -p ferrum2-crypto --test primitive_vectors --locked` |
| M0-CRYPTO-003 | AC-03/12 | SIP022 KDF output、key truncation与nonce-counter fixture | unit/KAT | `cargo test -p ferrum2-crypto --test sip022_vectors --locked` |
| M0-CRYPTO-004 | AC-03 | redacted secret、explicit-clear seam、entropy failure、salt collision、standalone counter与真实TCP AEAD owner nonce overflow | unit/negative | `cargo test -p ferrum2-crypto --test secret_entropy --locked`；`cargo test -p ferrum2-crypto --lib --locked` |
| M0-PROTO-001 | AC-04 | type/frame/address/padding/initial-payload bounds table | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked` |
| M0-PROTO-002 | AC-04 | 每个 authenticated chunk bit flip与 truncation | unit/negative | `cargo test -p ferrum2-shadowsocks --test tcp_negative --locked` |
| M0-PROTO-003 | AC-04/05 | timestamp `±30`/`±31` | fake-clock unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked` |
| M0-PROTO-004 | AC-04 | S0-S3 reject 前 connector/forward/accepted/replay mutation 全零 | instrumented integration | `cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked` |
| M0-PROTO-005 | AC-04 | one encrypt/one per-RX decrypt reusable scratch；fixed usable-limit request、stable identity、无reserve/per-frame growth；独立bounded Session payload owner | safe buffer-observer + private unit | `cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked`；`cargo test -p ferrum2-shadowsocks --lib --locked` |
| M0-PROTO-006 | AC-04/12 | 有独立provenance的非官方request/response composite wire fixture | protocol KAT | `cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked` |
| M0-PROTO-007 | AC-04/07 | response pending时client upload与server request RX公平推进；server Session target/payload精确且flow不重复payload；current/pending cipher ownership与Send+Unpin闭合 | opaque-flow integration | `cargo test -p ferrum2-shadowsocks --test tcp_duplex --locked` |
| M0-PROTO-008 | AC-04/06 | fixed 43/59 single completed operation不变；全部post-fixed region支持one-byte/mixed fragmentation，mid-region EOF按closed table终止；zero-length subsequent frame不产生伪EOF | scripted transport integration | `cargo test -p ferrum2-shadowsocks --test tcp_fragmentation --locked` |
| M0-PROTO-009 | AC-04/06/08 | 0/1/16384/16385 write admission、single-scratch backpressure、normal repeat polls、client response-pending时16385结构性边界仍非fatal且nonce/I/O failure精确、server response-pending时auth/bounds/nonce/I/O failure精确、零abortive、exact terminal matrix、source redaction | poll-state integration + private cipher-boundary unit | `cargo test -p ferrum2-shadowsocks --test tcp_flow_contract --locked`；`cargo test -p ferrum2-shadowsocks --lib --locked` |
| M0-REPLAY-001 | AC-05 | invalid不poison；valid same salt first accept/second reject | fake-state unit | `quality`完整执行`cargo test -p ferrum2-shadowsocks --test tcp_replay --locked`；focused诊断可使用full-name `--exact`但不是required allocation |
| M0-REPLAY-002 | AC-05 | 64-way duplicate 原子性 | concurrency | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked` |
| M0-REPLAY-003 | AC-05 | 59.999/60s retention与 wall rollback | fake-clock/state | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked` |
| M0-REPLAY-004 | AC-05 | capacity full fail closed，无 live eviction | state unit | `cargo test -p ferrum2-shadowsocks --test tcp_replay --locked` |
| M0-DETECT-001 | AC-06 | every scripted Detection；single completed initial I/O；terminal-installed event早于恰好一次`mark_abortive`，mark失败不恢复 | instrumented transport/observer | `cargo test -p ferrum2-shadowsocks --test detection_prevention --locked` |
| M0-DETECT-002 | AC-06/11 | 43个valid fixed-region prefixes `n=0..42`及独立authenticated auth/type/time/zero-length rows共47案；typed branches分别ShortRead/Authentication/InvalidType/TimestampSkew/AddressBounds，native均reset非EOF且每案target accepts=0 | native process/socket + independent generator | `platform/windows-msvc`与`platform/linux-gnu`各运行`cargo test -p ferrum2-m0-harness --test detection_probe --locked` |
| M0-DETECT-003 | AC-06 | runtime `AbortiveClose`只在mark时设置zero linger；normal paths不设置 | runtime socket integration | `cargo test -p ferrum2-runtime --test abortive_close --locked` |
| M0-BIND-001 | AC-06 | response full request-salt equality，bad binding不 forward | protocol integration | `cargo test -p ferrum2-shadowsocks --test response_binding --locked` |
| M0-SOCKS-001 | AC-07 | connector在first-write前存local endpoint；success bytes为`05 00 00 01`+该IPv4/port；双向 bytes | unit/integration | `cargo test -p ferrum2-socks5 --locked`；`cargo test -p ferrum2-m0-harness --test local_e2e --locked` |
| M0-SOCKS-002 | AC-07 | auth/cmd/domain/IPv6/malformed negative；每个 request-stage failure为`05 REP 00 01 00000000 0000` | unit/negative | `cargo test -p ferrum2-socks5 --test negative --locked` |
| M0-ENDPOINT-001 | AC-07 | client connector只收到configured SS server endpoint、request只编码application target；opaque connect-complete capability被一次消费；`local_addr`恰好查询一次；error/non-IPv4时零 SIP022 first-write，composition发精确general failure | cross-crate ordering | `cargo test -p ferrum2-runtime --test local_endpoint --locked`；`cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked`；`cargo test -p ferrum2-socks5 --test negative --locked`；`cargo test -p ferrum2-client --locked` |
| M0-ADAPT-001 | AC-06/07/08/09 | client TokioConnector/Transport/Framed机械delegation、initialized ReadBuf、Pending/call count、stored endpoint、fixed io::Error/source redaction；paused time以non-default durations和defaults证明configured connect与fresh configured request-first-write budgets、SOCKS success timing及timeout sole-owner drop；`test-util`只由ADR-0013 client dev edge启用；configured-SS Connect=`shadowsocks/failed`及全部terminal→Reason/stage/outcome mappings | binary unit integration | `cargo test -p ferrum2-client --locked` |
| M0-ADAPT-002 | AC-06/07/08/09 | server TokioTransport/Framed delegation；direct connect Pending/failure时零payload poll/forward；prefix partial writes只在nonzero progress重置idle，cancel/timeout/write-zero/error均保留精确count且不启动relay；paused-time capability只由ADR-0013 server dev edge启用；成功后Session.initial_payload恰好一次；direct Connect=`direct/failed`及全部terminal含Normal的observability mapping | binary unit integration | `cargo test -p ferrum2-server --locked` |
| M0-E2E-001 | AC-07 | 两真实 binary local echo + half-close + cleanup | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked` |
| M0-E2E-002 | AC-07 | pre-success protocol failure与 post-success target refusal | process E2E | `cargo test -p ferrum2-m0-harness --test local_e2e --locked` |
| M0-LIFE-001 | AC-08 | stalled writer停止 upstream read；buffer/permit cap | deterministic I/O | `cargo test -p ferrum2-runtime --test backpressure --locked` |
| M0-LIFE-002 | AC-08 | handshake/connect/idle timeout、cancel、listener failure；connect与request first-write budgets独立；relay failure保留每方向partial stats | fake-time integration | `cargo test -p ferrum2-runtime --test lifecycle --locked`；`cargo test -p ferrum2-client --locked` |
| M0-LIFE-003 | AC-07/08 | one-way EOF后 reverse drain | integration | `cargo test -p ferrum2-runtime --test half_close --locked` |
| M0-LIFE-004 | AC-08 | graceful drain/deadline/forced termination | process/integration | `cargo test -p ferrum2-runtime --test shutdown --locked` |
| M0-LIFE-005 | AC-08 | 黑盒full qualification复用一个matrix，五类contract rows与graceful/forced OS-signal row各20次，保证真实client/server starts分别100/120并证明child wait、三类ports与temp cleanup；Unix真实流量后exact地址立即bind+listen，Windows用无新控制台的child process group定向Ctrl-Break，live same-policy owner阻止第二listener；T06 direct counters及两个binary production-used registry composition tests先见live nonzero再回baseline，forced counter精确+1 | compositional deterministic repetition | `cargo test -p ferrum2-runtime --test lifecycle --locked`；`cargo test -p ferrum2-runtime --test shutdown --locked`；`cargo test -p ferrum2-client --locked`；`cargo test -p ferrum2-server --locked`；`cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked`；`cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture` |
| M0-OBS-001 | AC-09 | JSON schema + sentinel secret/destination scan | integration/snapshot | `cargo test -p ferrum2-observability --test tracing_contract --locked` |
| M0-OBS-002 | AC-09 | exposition names/types/labels/cardinality | integration/snapshot | `cargo test -p ferrum2-observability --test metrics_contract --locked` |
| M0-OBS-003 | AC-09 | runtime-owned `/metrics` permits/timeout/header/method bounds | runtime integration | `cargo test -p ferrum2-runtime --test metrics_endpoint --locked` |
| M0-INT-001 | AC-10/12 | ferrum client→sing-box server | required external E2E | `interop` Cargo-managed qualification summary row `M0-INT-001` |
| M0-INT-002 | AC-10/12 | ferrum client→shadowsocks-rust server | required external E2E | same driver summary row `M0-INT-002` |
| M0-INT-003 | AC-10/12 | sing-box SOCKS client→ferrum server | required external E2E | same driver summary row `M0-INT-003` |
| M0-INT-004 | AC-10/12 | shadowsocks-rust client→ferrum server | required external E2E | same driver summary row `M0-INT-004` |
| M0-PLAT-001 | AC-11 | Windows MSVC release build + artifact config run | native build/run | `platform/windows-msvc` commands in Compatibility matrix |
| M0-PLAT-002 | AC-11 | Linux GNU release build + artifact config run | native build/run | `platform/linux-gnu` commands in Compatibility matrix |
| M0-PLAT-003 | AC-11 | Linux musl release build + artifact config run/link evidence | build/run | `platform/linux-musl` commands in Compatibility matrix |
| M0-GATE-001 | AC-11 | authoritative local quick gate | repository gate | planning/integration：`workflow.toml` `[validation].quick` 每项 exit 0；不在hosted重复 |
| M0-GATE-002 | AC-11 | authoritative full gate | integration/hosted gate | local integration执行`workflow.toml` full；hosted `quality`先`cargo build --workspace --bins --locked`再执行full，每项exit 0 |
| M0-CI-001 | AC-11 | 唯一workflow path、exact trigger allowlist、拒绝`pull_request_target` | review + hosted instantiation | Architect/QA diff review；新run实际trigger/workflow identity |
| M0-CI-002 | AC-11 | initial四definitions/六rendered results、fixed runner mapping、bounded timeout、platform fail-fast false | review + hosted result | workflow diff；同run六项result inventory |
| M0-CI-003 | AC-11 | permissions、checkout full SHA/options、所有`uses:` full SHA | review + hosted log | workflow diff；checkout/job logs |
| M0-CI-004 | AC-11 | full只运行一次、current-SHA clean builds、no-cache、无cross-job ferrum artifact、本机不执行external entry | behavior + review | metadata确认Cargo-managed `test = false` binary；local quick/full；workflow diff；job logs |
| M0-CI-005 | AC-10/11 | musl/GNU/native outcome、reference verify-before-execution、synthetic-no-secrets | hosted evidence | platform/interop logs及四案summary |
| M0-CI-006 | AC-11 | 一个pushed exact integration SHA、单一run ID/attempt的六项close evidence | Team Lead/QA evidence review | GitHub workflow/run/job URLs、六项result与exact SHA review |
| M0-SCOPE-001 | AC-12 | planning base到exact candidate的ticket ownership、non-goal、dependency与provenance review | focused checks + Architect/QA review | `git diff --name-status --find-renames <planning-base>...HEAD`；`git diff --check <planning-base>...HEAD`；`cargo tree --workspace --locked`；fixture/reference provenance与resolved policy tests |

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

M0-CI-001～006 不再由 repository code解析repository workflow。实现前后由
Team Lead、Architect与QA直接审阅唯一workflow diff，检查：

- path、trigger allowlist及`pull_request_target`拒绝；
- 四个definitions、三个explicit platform cells、`fail-fast: false`、fixed
  runners、bounded timeout与无`continue-on-error`；
- top-level read-only permissions、无job elevation、checkout full SHA/options、
  所有`uses:` full SHA；
- quality binary build+full只运行一次、MSRV check/test、platform/interop current-SHA
  self-build、无cache或cross-job ferrum artifact；
- musl static assertions、GNU/Windows native detection、reference
  verify-before-run、四案aggregation和无`secrets.*`；
- close evidence关联one pushed exact integration SHA、one run ID/attempt及六项
  rendered results。

`cargo metadata`与workspace policy证明qualification是Cargo-managed
`test = false` binary；local quick/full证明它可编译/lint但不执行entry或external
case。少量pure state tests只覆盖guard/aggregation/failure continuation/summary，
不创建socket/process或访问network。workflow syntax/matrix/result只有实际hosted
instantiation才能证明。
M0-CI-006由Team Lead/QA审阅workflow/run/job URL、run ID/attempt、六项result和
`GITHUB_SHA`；不存在用第二套YAML parser提前伪造PASS的路径。

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

`ferrum2-m0-harness`不链接任何concrete ferrum2 crate。`quality`的full gate先运行
`cargo build --workspace --bins --locked`，harness从metadata target directory定位
当前platform binaries；artifact缺失即失败。

### External interoperability

四个M0-INT cases不再是Cargo/libtest targets，不使用`#[ignore]`、filter或count。
Cargo-managed `m0-qualification` binary读取`tests/interop/versions.toml`，manifest
设置`test = false`。metadata/check/Clippy和workspace policy覆盖它；quick/full、
all-features/all-targets可编译/lint但不执行其entry或external cases。只有
`interop` job在fresh `ubuntu-24.04` VM验证current `GITHUB_SHA`、运行
`cargo build --workspace --bins --locked`和
`cargo build -p ferrum2-m0-harness --bin m0-qualification --locked`，再执行该
binary。默认local tests最多运行无I/O的pure qualification state tests。

driver分别provision两个references。archive只下载到runner temp，必须先核实
ADR-0006固定的size/SHA-256/license record，再safe extract，并在对应case前核实
固定version output；unexpected archive entry同样失败。一个reference的provision
失败时，其两案以同一setup root报告FAIL且不得声称执行；它不能阻止另一个
reference的两案运行。缺环境、下载失败、checksum/version
mismatch、readiness timeout、child crash、case timeout或cleanup failure均记录为
对应FAIL；最终固定输出M0-INT-001～004四行，每行只有case ID、PASS/FAIL和可选
canonical root，只有4/4成功才exit 0。配置只使用
`AAECAwQFBgcICQoLDA0ODw==` synthetic PSK，不读取repository secrets。

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
- 默认`lifecycle_smoke_runs_each_category_once`对六个既有category各运行1次；
  ignored full qualification由authoritative full gate按exact name显式运行，每类20次，
  保证真实client/server starts分别为100/120。两者复用同一个matrix helper；每个child
  timed-waited，proxy/metrics/target原地址逐一重绑，temporary path不存在，harness
  child registry回起点。黑盒结果不得声称直接观察进程内counter。
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

`platform/windows-msvc` 在 `windows-2022`：

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

`platform/linux-gnu` 在 `ubuntu-24.04`：

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

`platform/linux-musl` 在 `ubuntu-24.04`：

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

每个platform cell记录runner label、`ImageOS`、`ImageVersion`、run identity、
OS/kernel、`rustc -Vv`、Cargo和artifact SHA-256；GNU/musl另记录适用的ELF/
linkage结果，Windows记录native PE执行结果。
GitHub-hosted VM 不提供本项目可固定的 OCI image digest；这些 provider-native
字段只批准为 M0 smoke evidence，不是 M3 完整平台 qualification。

MSRV 在 `ubuntu-24.04` 先执行
`rustup toolchain install 1.85.0 --profile minimal`，再执行
`cargo +1.85.0 check --workspace --all-targets --locked`及
`cargo +1.85.0 test --workspace --locked`。1.97.1 current behavior gate不能
替代MSRV实际test execution；qualification binary可被check/build但其
`test = false` entry和external cases不在MSRV libtest execution中。

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

ADR-0017删除`scope_audit.rs`、workflow parser、blob/path snapshot和mutation
self-audit。它们与被测workflow由同一commit维护，不能形成独立安全边界，并且已
引入未声明的runner `rg` dependency。用户明确要求忽略的skill optimization不再
进入M0 automated scope/provenance scan。

M0-T09/T10以接受的planning commit作为immutable implementation base。Team Lead、
Architect与QA对每个ticket和最终integration的
`git diff --name-status --find-renames <exact-base>...HEAD`、
`git diff --check <exact-base>...HEAD`及`cargo tree --workspace --locked`
明确签署以下checklist：

- 所有变更落在批准的 M0 product/control ownership，未实现 AES-256、ChaCha、UDP、
  public UDP inbound、domain/DNS、multi-user/EIH、routing/management 或性能范围；
- 无 real secret、production endpoint、外部 binary、generated result或未审 fixture；
- production dependency/member/method surface、unsafe/zeroize/secret policy与
  批准baseline一致；qualification是Cargo-managed、workspace-linted且
  `test = false`，不改变production graph；manifest只删除旧external test target/
  unused dev edges并增加不执行的binary target，不引入unreviewed dependency；
- T02/T03 fixtures与两个 reference pins的来源、hash、license-or-rights review和
  非分发策略完整；
- workflow只有批准的trigger/security/profile，未添加secret、write permission、
  cache dependency、artifact publication或remote effect。

focused `architecture`、`workspace_policy`、fixture provenance和resolved graph
tests继续运行，但不得重新解析整个workflow、固定job count/source spelling或复刻
Git历史。任何profile substitution仍须先更新ADR/SPEC/TEST/ticket mapping，在新
exact SHA上执行并通过独立review。

## Exit conditions and known gaps

M0 test gate通过需要：

1. 表中 M0-WS～M0-CI～M0-SCOPE 每个 required ID有同一 integrated commit 的
   PASS evidence。
2. `workflow.toml` quick/full所有命令实际运行且 exit 0。
3. 四项 interop与三项 platform smoke无 skip/缺失。
4. 另行授权push后，同一GitHub Actions run ID/attempt的六个预期rendered
   results对exact integration `GITHUB_SHA`全部success，完整workflow conclusion
   success且run identity/runner/toolchain evidence完整。
5. Architect与QA复核 spec符合性、security ordering、ownership和 evidence。
6. 未发现 committed external/generated artifact、real secret或M0 non-goal。

已知但明确延期：

- AES-256/ChaCha和完整地址/TCP matrix：M1。
- UDP/replay window/session limits：M2。
- 全平台长期 lifecycle和最终 operator stability：M3。
- throughput、10,000 idle与长期资源阈值：M4。

T01～T08 reviewed implementation先汇合到exact `5969bfd`；其hosted run
`30322690937`为6/11 success、5/11 failure并永久保持失败，未与后续证据拼接。
ADR-0017及M0-T09/T10随后在exact `8318ef1`完成local、Architect与QA再资格；
separately authorized run `30331336772` attempt 1的六项rendered results与完整
workflow均success，因此上述M0 test gate条件现已全部满足且没有open test blocker。
failure语义不变：required job启动后的
setup/network/package/reference/command/timeout/evidence失败是FAIL；workflow、
未授权push、provider或job未产生结果是BLOCKED。missing/skipped/cancelled/
neutral不会转换为waiver或PASS。
