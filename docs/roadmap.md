# ferrum2 v0 路线图

## 状态词汇与当前状态

里程碑状态为 `proposed` → `planned` → `executing` → `validating` → `closed`。
状态必须由 contract、ticket、commit 和验证证据支持。

Bootstrap 基线是
`master@b41c6127b1834ebd97246451fd92bafea50cb205`。M0 已进入 `executing`，
M1-M4 仍为 `proposed`。M0-T01 的 locked workspace、core contracts 与静态
policy tests 已在 `master@d9a641fecb2088fc1813ef4ebc58df392be48d64`
完成 integration；这只证明 AC-01 的当前切片，不证明后续产品行为或远程 CI。

## 依赖顺序

| 里程碑 | 依赖 | 可独立验收的主结果 |
|---|---|---|
| M0 | bootstrap 文档完成 | AES-128-GCM TCP 端到端安全纵切 |
| M1 | M0 closed | 三种方法的完整 TCP 与 12 项 TCP 互操作矩阵 |
| M2 | M1 closed | 三种方法的 UDP 协议 path 与 12 项 UDP 互操作矩阵 |
| M3 | M1、M2 closed | 运维契约、生命周期和三目标平台资格 |
| M4 | M3 closed | 性能/资源门及同一 commit 上的 v0 资格证明 |

M1 与 M2 都依赖 shared crypto/wire/runtime boundary；在 M1 冻结这些 contract
前不并行实施 M2。每个里程碑内的并行 ticket 仍须满足 dependency-ready 和
non-overlapping ownership。

## M0 — AES-128-GCM TCP 安全纵切

- **Status:** executing
- **Objective:** 建立第一个真实、可观察的产品路径：两个独立二进制在离线验证
  typed TOML 后，通过 SOCKS5 TCP `CONNECT`、SIP022
  `2022-blake3-aes-128-gcm` 和 server direct outbound 完成 local TCP echo。
- **Entry conditions:**
  - bootstrap 的 vision、gap analysis、roadmap、CI baseline 已更新并通过
    workflow validation；
  - `ADR-0001`～`ADR-0010` 已 Accepted，关闭 DEC-001～DEC-007、
    DEC-011～DEC-013；ADR-0009 仅修正 AEAD state zeroize feature
    unification，ADR-0010冻结opaque duplex contract；
  - `SPEC-0001` 与 `TEST-0001` 已 Approved；
  - M0-T01～M0-T08 的 blockers、non-overlapping ownership 和量化 acceptance
    已通过 workflow validation。
- **Exit criteria:**
  1. Cargo workspace、planned crates、两个 composition roots、pinned MSRV/
     dependencies、`Cargo.lock`、`GPL-3.0-only` metadata 和 workspace
     `unsafe_code = "forbid"` 已建立。
  2. 两个二进制的合法 synthetic TOML 离线校验成功；不受支持的方法、错误
     base64、错误 AES-128 key 长度、配置内部 endpoint 冲突和其他已定义语义错误
     在创建 listener 前以不泄密错误失败；OS 端口占用只属于 run-mode bind error。
  3. SOCKS5 `CONNECT` 经 AES-128 SIP022 client/server 到 direct TCP echo
     的成功、目标失败和 protocol failure 路径可重复测试。
  4. KDF/AEAD known-answer、message type、frame/address bounds、request/
     response binding、篡改、截断、超过 30 秒时间戳和 60 秒内 exact salt replay
     测试通过；失败发生在 target connect、peer-sized allocation、forwarding
     和 accepted-state mutation 之前。
  5. covered path 的 queue/buffer 有界；timeout、cancellation、TCP half-close、
     listener failure 和 graceful shutdown 不泄漏 task/socket/buffer。
  6. 最小 structured tracing 和 Prometheus-compatible metrics 可用；secret、
     derived material 和 salt/nonce 不出现在日志、错误、trace 或 labels；
     destination 不成为 label，labels 有固定枚举。
  7. ferrum2 与固定版本 sing-box、shadowsocks-rust 分别完成 AES-128 TCP
     双向互操作，共 4 个 required cases。
  8. `workflow.toml` quick/full gates 通过；`x86_64-pc-windows-msvc`、
     `x86_64-unknown-linux-gnu`、`x86_64-unknown-linux-musl` 对两个 release
     binaries 完成 locked build 与 matching-runner offline config smoke；
     GNU/Windows M0-DETECT-002、musl `file`/`readelf` static evidence 完整。
     另行授权 push 后，GitHub Actions 一个 run ID/attempt 的 11 个固定 job 在
     exact integration `GITHUB_SHA` 全部 success。
- **In-scope tickets:**
  - M0-T01：locked workspace、toolchain、license 与 core contracts；原 integration
    已 done，现依用户授权为 ADR-0009 的一次独占 manifest repair reopen，且为
    candidate `edaee3d` Architect/QA ticket gates PASS，integration `4f3f0ac`
    gates PASS，done；
  - M0-T02：secret/KDF/AEAD/key-clock-entropy；原 combined integration
    `f9e218e` Architect/QA 与 70 tests PASS；T03 nonce-exhaustion blocker引发的
    窄幅reopen已由candidate `6a058035`和integration `bb5c47ec`关闭，只增加
    crate-private `cfg(test)`真实`TcpSealer`/`TcpOpener` owner exhaustion；
    exact 2/2及全部T02 commands、ticket/integration Architect/QA PASS，done；
  - M0-T03：SIP022 TCP security state/replay/binding；candidate `05605d3`
    Architect/QA BLOCK；fixed/reusable scratch与negative/order evidence不完整，
    且typed transition无法组成concurrent duplex relay、丢失authenticated initial
    payload并拒绝合法post-fixed fragmentation。修复前需要显式冻结split/fatal-error
    concurrency interface；Product scope triage确认不扩大M0产品/wire范围，用户
    已授权后续全部M0内本地窄blocker。ADR-0010保留core
    `Session.initial_payload`、选择opaque unsplit duplex flow并冻结exact terminal/
    adapter evidence；repair 1/2关闭production缺陷，repair 2/2补强多数证据但最终
    Architect/QA拒绝public hidden nonce hooks、release flags与扩大的observer
    callback，并要求补齐Detection/client admission。用户授权的额外窄修复
    `3a9114d`关闭全部finding；integration首轮发现Windows CRLF provenance
    checkout缺陷，隔离修复`1f76597`仅规范化文本哈希语义。最终checkpoint
    `4bf758a`上15项ticket commands、T02 exact 2/2、T03 exact 4/4、
    release/Clippy/fmt及组合Architect/QA gates全部通过，done；本地授权不改变
    原T08 conditional exact-SHA push边界；
  - M0-T04：typed config/observability；initial candidate `e9c6b01`
    Architect/QA BLOCK；repair 1/2 candidate `8d18d17` 已关闭 exact-target
    tracing spoof 与 server unknown-field evidence，ticket与integration
    Architect/QA全部PASS，integrated `5e3ddf9`，done；
  - M0-T05：SOCKS5 CONNECT inbound；done；
  - M0-T06：runtime/direct/relay/lifecycle；done；
  - M0-T07：binary composition/local E2E；全部依赖已完成，ready；
  - M0-T08：GitHub Actions workflow、interop/MSRV/platform/integration gates；
    独占 `.github/workflows/m0.yml`，blocked by T07。

  Dependency graph：

  ```text
  M0-T01
   ├─ M0-T02 ─┬─ M0-T03 ─┐
   │           └─ M0-T04 ─┤
   ├─ M0-T05 ─────────────┼─ M0-T07 ─ M0-T08
   └─ M0-T06 ─────────────┘
  ```
- **Deferred/out of scope:** AES-256、ChaCha20-Poly1305、UDP、完整 release
  qualification 和正式性能门；这些只延期到 M1-M4，不从 v0 删除。
- **Integrated commit:** 当前 validated checkpoint
  `4bf758ae76421856bb527db3afe165d47e6fd4aa`，包含
  M0-T01～M0-T06；T03票据级门禁与组合证据已通过，workspace quick/full仍等待
  T07/T08完成缺失的binary/harness入口。
- **Open blockers and risks:** M0-T05 与 M0-T06 已完成 ticket/final
  Architect、QA 和 integration gates；M0-T06 使用 repair 1/2 关闭了
  shutdown/accept race 与生命周期证据缺口。M0-T02 验证发现 ADR-0004 固定的
  CAVP ZIP 不含批准的两组 numeric cases；ADR-0008 窄勘误已经显式授权并把
  provenance 更正为 McGrew/Viega GCM proposal `vec-01`/`vec-02`。向量与协议
  行为不变，contract Architect/QA 均已 PASS。T02 commit `df22d7e` 已关闭
  provenance 与 `NonceCounter` findings；后续 dependency review 又确认
  `aes-gcm/zeroize` 没有启用 `aes/zeroize`/`ghash/zeroize`。用户已授权 ADR-0009
  与一次独占 T01 manifest repair，只允许 fixed `aes 0.9.1`/`ghash 0.6.0`
  zeroize feature anchors、lock 与 policy evidence，不改变版本、wire/API 或产品
  范围。T01/T02 combined integration `f9e218e` 已通过 Architect/QA 与
  70 tests。T04 repair 1/2 与 integration `5e3ddf9` 已通过全部ticket、
  regression、Architect与QA gates。ADR-0010及同步SPEC/TEST/T03/T07窄修订已获
  Product/Architect/QA PASS并在`d0e7e38`接受。T03 repair 1/2 `8d772f4`
  关闭opaque duplex/state缺陷；repair 2/2 `2ce254f`补强多数direct evidence，
  但final Architect/QA拒绝public hidden nonce hooks、release flags与扩大的
  `BufferObserver` callback，并要求补齐client pending admission/Detection rows。
  T02的2个crate-private真实AEAD owner tests已在candidate `6a058035`和
  integration `bb5c47ec`通过全部Team Lead/Architect/QA gates并恢复done。
  T03从保留的`2ce254f`恢复后，使用用户明确授权的一次额外窄修复`3a9114d`，
  移除所有public/release test seam并增加4个private mapping/capacity unit，
  同时补齐Detection/admission evidence。Windows CRLF provenance blocker由
  `1f76597`窄修复；最终integration `4bf758a`的T02 2/2、T03 4/4与全部T03 gates
  经Architect/QA通过，T03已done。全局repair budget不变；T07现ready，T08等待T07。
  GitHub Actions provider 已由 ADR-0007 固定；origin URL 与只读访问已验证，
  但 push/workflow execution 尚未发生。matching hosted runner/reference download
  不可用会在 T08 成为 hard blocker，不能 skip，也不能用本机 WSL2 代替。
  AEAD nonce reuse、secret leakage、认证前副作用和 task leak 仍是 P0 实现风险，
  其控制合同见 ADR-0002/0004/0005 与 TEST-0001。

## M1 — 完整 TCP 与 TCP 互操作

- **Status:** proposed
- **Objective:** 在不复制 transport state machine 的前提下，将 TCP 扩展到
  三个指定方法并完成完整 reference interoperability。
- **Entry conditions:** M0 closed；AES-128 wire/runtime/key lookup contract
  经实测稳定；reference versions 和 fixture provenance 已固定。
- **Exit criteria:**
  1. AES-128、AES-256、ChaCha20-Poly1305 分别通过 KDF/AEAD KAT、SIP022
     TCP 正负向、replay、binding 和 detection-prevention suite。
  2. IPv4、IPv6、domain target、错误地址、目标拒绝、TCP half-close 和
     cancellation/error mapping 行为均有 acceptance-mapped 测试。
  3. `3 methods × 2 reference implementations × 2 directions = 12`
     个 TCP required interop cases 全部通过；required case 不因环境缺失静默跳过。
  4. M0 security、resource、observability、platform smoke 和 host full gate
     回归通过。
- **In-scope tickets:** none yet；由 M1 `plan` 创建。
- **Deferred/out of scope:** UDP、最终平台 qualification 和 performance gate。
- **Integrated commit:** not yet
- **Open blockers and risks:** reference behavior/version drift、fixture license、
  method abstraction 对 hot path 的额外 allocation/dispatch，以及为兼容性静默
  偏离 SIP022 的风险。

## M2 — 完整 UDP 协议纵切与 UDP 互操作

- **Status:** proposed
- **Objective:** 通过 protocol API 和 server direct UDP path 交付三个方法的
  SIP022 UDP，不新增 SOCKS5 `UDP ASSOCIATE` 等公开 inbound。
- **Entry conditions:** M1 closed；shared cipher/key lookup/wire contract 稳定；
  UDP state/session spec 和资源 test plan 已批准。
- **Exit criteria:**
  1. 三个方法分别通过 UDP KAT、header/address/bounds、tamper/truncation、
     session/request-response binding 和 semantic failure tests。
  2. session ID/packet ID 不造成 AEAD key/nonce pair reuse；packet ID
     per direction monotonic，sliding window per direction 独立。
  3. replay window 只在 authentication 和完整 semantic header validation
     成功后原子更新；所需 replay state 至少保留 60 秒。
  4. session count、buffered bytes、idle lifetime、channels/queues 均有明确
     limit；背压、并发回收、timeout/cancellation 和 graceful shutdown 无泄漏。
  5. protocol API 到 direct UDP echo 的成功/失败路径通过；三个方法的
     `3 × 2 references × 2 directions = 12` 个 UDP interop cases 全部通过。
  6. M0/M1 回归和 `workflow.toml` full gate 通过。
- **In-scope tickets:** none yet；由 M2 `plan` 创建。
- **Deferred/out of scope:** public UDP inbound、SOCKS5 UDP ASSOCIATE。
- **Integrated commit:** not yet
- **Open blockers and risks:** UDP API ownership、window/session limits、
  concurrent eviction、packet reordering 和 state mutation ordering 尚未决；
  per-packet allocation/copy 优化不能削弱认证或边界。

## M3 — 运维、生命周期与平台资格

- **Status:** proposed
- **Objective:** 冻结并验证两个二进制的 operator-facing contract、全路径资源
  生命周期和三目标 release build，使已完成的 TCP/UDP 能可靠部署和诊断。
- **Entry conditions:** M1、M2 closed；功能/wire contract 冻结；目标 toolchain、
  linker/runner 和 artifact smoke contract 已批准。
- **Exit criteria:**
  1. client/server 最终 TOML schema、CLI validation/exit/error semantics 和
     synthetic examples 通过 compatibility tests；所有 semantic error 都先于
     runtime resource creation。
  2. tracing fields、levels、redaction 和 Prometheus exposition/metric names/
     labels 已记录为 stable contract；不含 secret 或 destination labels，
     cardinality tests 通过。
  3. TCP/UDP 的 cancellation、timeout、listener failure、half-close、
     graceful shutdown、bounded queue/session 和 repeated lifecycle/soak
     tests 无 task/socket/buffer/session leak。
  4. Linux x86_64 glibc、Linux x86_64 musl、Windows 的 locked release
     build 以及产物级离线配置 smoke 全部通过。
  5. security、interop、platform matrix 和 `workflow.toml` full gate 在同一
     integrated commit 通过并记录在 CI status。
- **In-scope tickets:** none yet；由 M3 `plan` 创建。
- **Deferred/out of scope:** performance qualification 和 v0 之外功能。
- **Integrated commit:** not yet
- **Open blockers and risks:** 精确 target triple、musl/linker、Windows socket
  differences、metrics exposure default、artifact retention 和 long-running
  runner availability。

## M4 — 性能、资源与 v0 资格确认

- **Status:** proposed
- **Objective:** 在功能和平台 contract 冻结后建立可复现基线，并证明同一
  integrated commit 满足全部 v0 release gates；本里程碑不执行发布。
- **Entry conditions:** M3 closed；benchmark hardware、toolchain、reference
  version/config、load profile、warm-up/repetitions/statistics 和 resource
  stability threshold 已在 spec/test plan 中固定。
- **Exit criteria:**
  1. 同机可比配置下，ferrum2 loopback aggregate TCP throughput 至少为
     shadowsocks-rust 基线的 90%，原始结果和复现说明被保存为不提交仓库的
     generated artifact。
  2. 10,000 idle TCP sessions 在预先约定的 soak/采样窗口内，task count
     和 memory 不持续增长并满足预定稳定阈值。
  3. 全部 24 个 required interop cases、security/resource suite、三目标
     build/artifact smoke 和 `workflow.toml` full gate 在同一 commit 通过。
  4. v0 未决 P0/P1 blocker 为零；已知 debt、deferred scope 和 evidence
     可供 `mode: close` 审核及 handoff。
- **In-scope tickets:** none yet；由 M4 `plan` 创建。
- **Deferred/out of scope:** SIP023、多用户、公开 UDP inbound、routing、DNS
  proxy、multi-upstream、load balancing、proxy chaining、hot reload、
  management API、reduced-round ChaCha、custom executor 和 `io_uring`。
- **Integrated commit:** not yet
- **Open blockers and risks:** benchmark 等价性、runner 噪声、稳定阈值和
  结果归档尚未决；性能压力不得绕过 `unsafe` policy、安全或 backpressure。

## 决策登记

| ID | 状态 | 决策/延期边界 | Contract/evidence |
|---|---|---|---|
| DEC-001 | resolved in M0 plan | official-site SIP022 commit/blob；Rust 1.97.1 build、MSRV 1.85.0、exact dependencies、GPL-3.0-only | `ADR-0001`、upstream baseline |
| DEC-002 | resolved in M0 plan | 十个 workspace members、one-way DAG、runtime-neutral RPITIT core contracts、T01 manifest ownership | `ADR-0001`、`SPEC-0001` |
| DEC-003 | resolved in M0 plan | secret newtypes/capability key provider、future selector seam、separate wall/monotonic clock、OS CSPRNG | `ADR-0002` |
| DEC-004 | resolved in M0 plan | schema v1、strict typed TOML、`--config/--check-config`、0/1/2 exits、redacted error taxonomy | `ADR-0003` |
| DEC-005 | resolved in M0 plan | full-auth/semantic-before-replay ordering、exact 60s/capacity fail-closed、single I/O、zero-linger、binding | `ADR-0004` |
| DEC-006 | resolved in M0 plan | one owner task、no data channel、numeric time/buffer caps、half-close/shutdown、fixed trace/metric schema | `ADR-0005` |
| DEC-007 | resolved in M0 plan | sing-box 1.13.14、shadowsocks-rust 1.24.0、asset hashes、unavailable=FAIL/BLOCK、three exact targets | `ADR-0006`、upstream baseline |
| DEC-008 | open；M2 plan | UDP protocol API、window/session/buffer/idle limits 与 eviction | M0 明确不实现 UDP |
| DEC-009 | partially bounded；M3 plan | M0 已固定 triples/build/config smoke；full native lifecycle/packaging qualification 留 M3 | `ADR-0006` |
| DEC-010 | open；M4 plan | benchmark hardware/config/statistics 与 10k-idle stability threshold | M0 不设性能声明 |
| DEC-011 | resolved in M0 CI amendment | GitHub Actions required provider；`.github/workflows/m0.yml`；fixed hosted runners/jobs/security/evidence；本机 WSL2仅作诊断 | `ADR-0007`、`SPEC-0001`、`TEST-0001`、M0-T08 |
| DEC-012 | resolved in M0 narrow amendment | fixed `aes 0.9.1`/`ghash 0.6.0` no-default `zeroize` direct feature anchors，使 `aes`/`ghash`/`polyval` keyed state drop-zeroize；exact resolved feature/package-ID 与 110-tuple lock identity evidence；无版本/wire/API/scope变化 | `ADR-0009`、`ADR-0002`、M0-T01/M0-T02 |
| DEC-013 | resolved in M0 narrow amendment | opaque unsplit SIP022 flow、configured-server/application-target separation、core `Session.initial_payload` ownership、executor-neutral polling、direction-local normal close、single fatal arbitration与binary-local Tokio adapters；无wire/product/core/runtime/manifest变化 | `ADR-0010`、`SPEC-0001`、`TEST-0001`、M0-T03/M0-T07 |

## 风险登记

| 风险 | 等级 | 最早控制点 | 控制方式 |
|---|---|---|---|
| SIP022/AEAD/nonce/replay 实现错误 | P0 | M0 | approved ADR/spec、KAT、负向测试、双向互操作 |
| AEAD expanded key/GHASH state 未启用上游 drop-zeroize | P0 | M0 | ADR-0009 exact feature anchors、metadata/package-ID/lock-identity policy、Cargo tree、T01/T02与integration双 gate |
| 认证前 connect/allocate/mutate | P0 | M0 | explicit connector/allocation/state test seams |
| secret 泄漏、destination 成为 metric label 或 cardinality 爆炸 | P0 | M0 | secret types、redaction tests、fixed labels |
| task/session leak、unbounded queue 或错误 half-close | P0 | M0 | owner/termination contract、bounded tests、soak |
| 外部实现/fixture/version/license 漂移 | P1 | M0 | pin/checksum/provenance 和 required-job policy |
| musl/Windows 差异发现过晚 | P1 | M0 | early build smoke，M3 full qualification |
| GitHub-hosted image weekly drift 或 provider outage | P1 | M0 | fixed OS labels、ImageOS/ImageVersion/Included Software evidence、unavailable=FAIL/BLOCK；不宣称M3资格 |
| benchmark 不等价或噪声驱动错误优化 | P1 | M4 | frozen comparable config 和重复统计 |
| 当前零代码使工期/接口估计不可靠 | P1 | M0 plan | 小型纵切、窄 tickets、每波 review/validation |

## 决策与范围变更日志

| Date | Milestone | Change | Reason | Evidence |
|---|---|---|---|---|
| 2026-07-27 | Bootstrap | 采用 M0→M4 的纵向路线，不扩大 v0 范围 | 尽早验证最高安全、互操作、平台和性能风险，同时保持每阶段可独立验收 | `AGENTS.md`、`workflow.toml`、仓库清点、Product/Architect/QA bootstrap reports |
| 2026-07-27 | M0 | 首个 plan 目标确定为 AES-128-GCM TCP 安全纵切 | 比纯 workspace scaffolding 更早产生可观察用户路径并验证 module seams | Product PASS_WITH_ACTIONS；Architect/QA 要求安全、生命周期、互操作和平台门前移 |
| 2026-07-27 | M0 plan | M0 改为 `planned`，接受 ADR-0001～0006、SPEC/TEST-0001 与 T01～T08 DAG | DEC-001～007 已有可实现、可测试、ownership-disjoint contract；唯一 initial frontier 为 T01 | Product/Architect/QA plan reports；upstream baseline；workflow validate/frontier/next |
| 2026-07-27 | M0 CI amendment | 以 GitHub Actions/GitHub-hosted runners 取代本机 WSL2 作为 M0 required CI；新增 ADR-0007 和 T08 的唯一 workflow ownership | 绑定 pushed exact integration commit，固定 native runners、11 job、安全与 provider-native evidence，同时不扩大产品/协议范围 | Product/Architect/QA amendment reports；GitHub official runner/security docs；workflow validate/frontier/next |
| 2026-07-27 | M0 duplex contract amendment | 接受opaque unsplit SIP022 flow取代T03 caller-managed transitions，同时分离configured SS server/application target、保留core Session initial-payload ownership与未修改runtime lifecycle | initial candidate无法并发duplex、丢失cipher/payload、拒绝合法fragmentation且无法证明scratch/fatal ownership；用户已授权本地窄blocker修复 | ADR-0010 Accepted；Product/Architect/QA PASS；workflow validate/diff-check |
