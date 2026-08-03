# ferrum2 v0 路线图

## 状态词汇与当前状态

里程碑状态为 `proposed` → `planned` → `executing` → `validating` → `closed`。
状态必须由 contract、ticket、commit 和验证证据支持。

Bootstrap 基线是
`master@b41c6127b1834ebd97246451fd92bafea50cb205`。M0 已以 exact integration
`8318ef106d6cd4e029bd3b02aa64125fabdda462`、本地 full gate 与 GitHub Actions
run `30331336772` attempt 1 的六项成功证据关闭；M1 已以 exact
`874c83d0ee71054bd702d6ecac55e88d9e2fbcef`、本地 full gate 与 GitHub Actions
run `30367147537` attempt 1 的六项成功证据关闭；M2 已以 exact
`7907cda05a56e1c3b85af2dd8faeb85a385154b7`、本地 full gate 与 GitHub
Actions run `30425476328` attempt 1 的六项成功、TCP/UDP 各 12/12 及 focused
IPv6 UDP real-process 证据关闭。M3 已由 exact qualified product
`d9e59d787c3fe78dfca778ee8a36668a45387368`、本地 full gate 与 GitHub
Actions run `30494736004` attempt 1 的七项成功、TCP/UDP 各 12/12、三目标
native lifecycle/linkage/hash 和关闭审查证据关闭；local closeout source 是
docs-only descendant `d784b06171723bb93fd467cea1a799f58f7d60b0`。M4已以exact
`9b379a426853d86a184464f6fd8c73081b464535`、GitHub Actions run
`30730883667/1`的performance、Full/security/process、MSRV、TCP/UDP `24/24`、
三平台、test budget和final qualification证据关闭；local closeout source是
docs-only descendant `a38a1e84c90a7e03c047eaa4e275fc7ed3410cdb`。M5已以exact
`6ca043460f0a5233a0b39c9931b4f3f3a22f1cba`、GitHub Actions run
`30743888837/1`的Full/security/process、MSRV、TCP与UDP各`12/12`、三平台、
performance/resource、test budget和final qualification证据关闭；本地closeout
source是该qualified SHA之后的专用docs-only提交。
M6已以exact `7f1e45c174e749d3dddd32d187365722cce94dbe`、本地Full/MSRV/budget、
GitHub Actions run [`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553)
的quality、MSRV、三平台和TCP/UDP各`12/12`+cleanup证据关闭。用户明确将这四组
定义为M6 hosted成功；未等待或声称performance及其dependent aggregate通过。
M7已在`master@302fd777f4da62a8c1d4d52d81502056f02089c8`规划为additive
schema v1 tagged static composition，并从exact ticket base `96a088e227dcfe415985c3deb081c807fb5e7d90`
进入`executing`；M7-T01～T03已集成，M7-T04 active，尚无M7资格或remote证据。
durable handoff 位于 `docs/handoffs/HANDOFF-M0-2026-07-28.md` 和
`docs/handoffs/HANDOFF-M1-2026-07-28.md`；M2 handoff 位于
`docs/handoffs/HANDOFF-M2-2026-07-29.md`，M3 handoff 位于
`docs/handoffs/HANDOFF-M3-2026-07-30.md`，M4/M5/M6 handoff 位于
`docs/handoffs/HANDOFF-M4-2026-08-02.md`、
`docs/handoffs/HANDOFF-M5-2026-08-02.md`和
`docs/handoffs/HANDOFF-M6-2026-08-03.md`。

## 依赖顺序

| 里程碑 | 依赖 | 可独立验收的主结果 |
|---|---|---|
| M0 | bootstrap 文档完成 | AES-128-GCM TCP 端到端安全纵切 |
| M1 | M0 closed | 三种方法的完整 TCP 与 12 项 TCP 互操作矩阵 |
| M2 | M1 closed | 三种方法的 UDP 协议 path 与 12 项 UDP 互操作矩阵 |
| M3 | M1、M2 closed | 运维契约、生命周期和三目标平台资格 |
| M4 | M3 closed | 性能/资源门及同一 commit 上的 v0 资格证明 |
| M5 | M4 closed | `shadowsocks-crypto`成为三种SIP022方法的唯一内部密码实现 |
| M6 | M5 closed | 显式opt-in、有界且可关闭的SOCKS5 UDP ASSOCIATE |
| M7 | M6 closed | 具名多inbound/outbound的静态tag绑定与原子启动 |

M1 已冻结并验证 shared crypto/wire/runtime boundary；M2 已冻结并验证
method-bound UDP crypto、packet/replay/session、bounded direct UDP runtime、
same-port composition、12 项 UDP interop 与 focused IPv6 direct-target
证据；M3 已冻结 operator/observability contract、统一 process lifecycle 并
完成三目标 native qualification。M4已在同exact SHA上完成可复现吞吐基线、
10,000 idle sessions资源资格、Full、interop和三平台收敛；v0 preview已获得
资格但未打包、发布或公开。M5已完成单实现迁移、安全patch与同SHA关闭资格，
公开crypto seam、协议状态机、wire和schema v1保持不变。M6已复用现有SIP022
UDP和runtime交付public client UDP path，未加入routing。M7计划复用config与
`ProcessSupervisor` deep modules，增加静态tag graph而不创建`Endpoint` interface。

## M0 — AES-128-GCM TCP 安全纵切

- **Status:** closed
- **Objective:** 建立第一个真实、可观察的产品路径：两个独立二进制在离线验证
  typed TOML 后，通过 SOCKS5 TCP `CONNECT`、SIP022
  `2022-blake3-aes-128-gcm` 和 server direct outbound 完成 local TCP echo。
- **Entry conditions:**
  - bootstrap 的 vision、gap analysis、roadmap、CI baseline 已更新并通过
    workflow validation；
  - `ADR-0001`～`ADR-0017` 已 Accepted；
    ADR-0016/0017区分normative invariant、
    selected conformance profile与mechanical realization，既有安全/协议/release
    结果不变，DEC-014～020已关闭；
  - `SPEC-0001` 与 `TEST-0001` 的ADR-0010～0017 amendments已Approved；
  - M0-T01～M0-T10均已done；T09/T10的implementation、integration、
    exact-SHA review与hosted evidence gates均已通过。
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
     另行授权push后，GitHub Actions一个run ID/attempt的六个预期rendered
     results在exact integration `GITHUB_SHA`全部success；job topology不是永久
     产品合同。
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
    原T08 conditional exact-SHA push边界。T07 preflight随后发现fused client open
    无法分别应用configured connect/fresh first-write deadlines（默认10秒/5秒）；
    现依ADR-0012窄幅reopen；candidate `8f0d1e0`已通过全部ticket commands，
    Architect/QA ticket gates及`2ce7708`组合integration gates均PASS，done；
  - M0-T04：typed config/observability；initial candidate `e9c6b01`
    Architect/QA BLOCK；repair 1/2 candidate `8d18d17` 已关闭 exact-target
    tracing spoof 与 server unknown-field evidence，ticket与integration
    Architect/QA全部PASS，integrated `5e3ddf9`，done；
  - M0-T05：SOCKS5 CONNECT inbound；done；
  - M0-T06：runtime/direct/relay/lifecycle；历史ticket/integration done；T07
    preflight发现failure outcome丢失partial forwarded stats，现依ADR-0012窄幅reopen
    只修复relay outcome与direct tests；candidate `756a379`已通过全部ticket commands
    与33个package tests，Architect PASS；QA mutation review发现read-ahead test在
    t=0不能杀死read误重置idle的突变；窄repair `0ef7969`用4s延迟read+最后1s
    deadline杀死该突变，全部ticket/package gates及Architect/QA复核PASS；
    `2ce7708`组合integration gate通过并done；
  - M0-T07：binary composition/local E2E；candidate `5ac8f1b`完成两个binary、
    CLI/adapters、configured paused-time phases、native 47-case probe与5×20
    lifecycle。Architect发现cooperative row未同步证明target flow；repair 1/2
    `a9b0a56`以valid client→server→target、bounded accept与EOF/reset ack关闭
    假阳性。ticket及integration Architect/QA、24条ticket commands、quick/full
    均PASS，integrated `91516720`。T08随后暴露Rust 1.85 let-chain不兼容；窄修复
    `50bf0b7`及integration `123618f`通过MSRV、focused、quick/full与最终
    Architect/QA gates；T08 QA后续发现100-cycle readiness flake，独立诊断以
    foreign-port probe确定为harness `AddrInUse` ownership TOCTOU，现只窄reopen
    local_support/lifecycle_cycles evidence；first candidate `1974935`经Architect
    BLOCK后由follow-up `6139544`加入causal metrics transition、absolute readiness
    deadline与显式retry cleanup，Architect PASS、QA PASS_WITH_ACTIONS并等待集成；
    `6139544`随后已集成于`51fb7327`并通过本地最终门禁，但首个hosted run
    `30301746374`在真实Linux流量后的exact rebind暴露`EADDRINUSE`。ADR-0015
    已接受并将修复限定为Unix-only production listener reuse、default Windows、
    same-policy bind+listen evidence和唯一`socket2` harness dev edge；T07再次
    窄reopen；
  - M0-T08：GitHub Actions workflow、interop/MSRV/platform/integration gates；
    独占 `.github/workflows/m0.yml`；ADR-0014 external evidence边界已接受；
    repair 1/2 `5accd02`通过大部分本地执行，但final Architect/QA因EOF顺序/
    deadline、workflow closed-subset及platform helper evidence缺口而BLOCK；
    final repair first candidate `3d5b1a2`关闭workflow/platform groups，但
    Architect要求补app EOF ack stream-hold与fixed operation deadline；
    follow-up `49c63082`关闭两项finding并获Architect PASS、QA
    PASS_WITH_ACTIONS；已与T07集成为`51fb7327`并通过same-SHA本地最终门禁。
    首个GitHub run `30301746374`为2/11 success、9/11 failure：两个interop
    success不可拼接，其余除T07 rebind外均为exact-filter、GNU/musl bare linker
    或Windows link-help evidence-script缺陷；T08按ADR-0015再次窄reopen。调度依赖已
    分为implementation与integration gate：T08的disjoint证据脚本修复可与active
    T07并行，但在T07 done前不得集成或进入release gate。该轮修复最终集成于
    `5969bfdafea9056feb179e0a8454dd5dc7fe5bce`，T01～T08均done；第二个
    hosted run `30322690937`为6/11 success、5/11 failure，lifecycle、GNU、
    musl与四项interop对应jobs已通过，剩余四个根因全部位于CI evidence seam。
  - M0-T09：建立Cargo-managed、`test = false`的hosted qualification；本机
    metadata/check/quick/full编译并lint它但不执行reference cases，hosted一次运行
    聚合四案且4/4才成功；integrated于`37aba8a`并done。
  - M0-T10：把workflow收敛为quality、MSRV、三平台matrix和interop四个
    definitions/六个rendered results；删除scope/YAML/snapshot自审计、
    filter/count、linker-help和重复Ubuntu jobs；final candidate `5ad65d6`，
    integrated于exact material SHA `8318ef1`并done。

  Dependency graph：

  ```text
  M0-T01
   ├─ M0-T02 ─┬─ M0-T03 ─┐
   │           └─ M0-T04 ─┤
   ├─ M0-T05 ─────────────┼─ M0-T07
   └─ M0-T06 ─────────────┘

  M0-T01 ── … ── M0-T08: done at 5969bfd
                        ├─ M0-T09 hosted interop seam: done
                        └─ M0-T10 workflow profile: done
  material integration: 8318ef1; hosted run 30331336772: 6/6 success
  ```
- **Deferred/out of scope:** AES-256、ChaCha20-Poly1305、UDP、完整 release
  qualification 和正式性能门；这些只延期到 M1-M4，不从 v0 删除。
- **Integrated commit:** 当前local/remote integration
  `8318ef106d6cd4e029bd3b02aa64125fabdda462`包含M0-T01～T10 reviewed
  implementation。GitHub Actions run `30331336772` attempt 1在该exact SHA
  整体success，quality、MSRV、Windows MSVC、Linux GNU、Linux musl与interop
  六项required results全部success；旧失败run保持历史记录。
- **Closeout:** 2026-07-28 close gate在`master@b0717d2`启动；Product、
  Architect与QA完成独立只读复核，Team Lead在exact integration SHA重跑
  `workflow.toml` full 4/4并写入durable handoff。close mode没有新增product
  repair、push、PR、tag或release。
- **Resolved blocker history and remaining deferred risks:** M0没有open
  canonical blocker；performance/10k-idle qualification按路线图留给M4。
  M0-T05 与 M0-T06 已完成 ticket/final
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
  经Architect/QA通过，T03历史checkpoint已done。T07 preflight又暴露两个跨module
  contract blocker：黑盒harness不能直接证明进程内owner counters且stale fixture
  不能认证type/time/length native branches；fused client open/relay error-only
  outcome分别阻止独立deadline和partial byte accounting。用户的后续本地窄blocker
  授权已覆盖该修订；ADR-0011/0012草案不改变wire/product/API/remote范围。
  Product对两项范围均PASS，Architect接受evidence设计并要求独立ADR-0012，QA要求
  exact two-edge lock delta与`AddressBounds` row；修订吸收全部findings后最终
  Product/Architect/QA document gates均PASS。T03 candidate `8f0d1e0`获Architect
  PASS、QA PASS_WITH_ACTIONS（仅T07后workspace quick）；T06 candidate `756a379`
  production获Architect PASS，repair `0ef7969`关闭QA mutation gap并获最终
  Architect/QA PASS。T03/T06通过`951806d`/`2ce7708`集成，组合Architect/QA
  PASS且normal/all-features各97 tests通过，均done。
  ADR-0013勘误base `24ddecf`已通过Product/Architect/QA final document gates
  并被接受；T07 candidate `5ac8f1b`与lifecycle evidence repair 1/2 `a9b0a56`
  已通过ticket/final Architect与QA gates并集成于`91516720`。后续MSRV repair
  `50bf0b7`与integration `123618f`同样通过Team Lead/final Architect/QA gates，
  T07的product/MSRV修复保持PASS，但readiness harness因deterministic
  foreign-port TOCTOU窄reopen。ADR-0014已在`96d6262`接受；T08 repair 1/2
  `5accd02`通过大部分本地执行，但final Architect/QA均BLOCK。final repair 2/2现集中关闭真实
  target→application EOF/shutdown顺序、absolute I/O deadline、closed workflow
  policy与observable platform evidence。T07 first candidate `1974935`被
  Architect BLOCK后，follow-up `6139544`已获Architect PASS、QA
  PASS_WITH_ACTIONS；T08 `3d5b1a2`后的follow-up `49c63082`也获Architect PASS、
  QA PASS_WITH_ACTIONS。两者随后已集成于`51fb7327`并通过local same-SHA
  Team Lead/Architect/QA gates；后续repair已汇合到`5969bfd`，T01～T08 done。
  repair budget现按canonical root ID及该根因risk计数；mechanical修复与派生失败不消耗substantive
  budget，最终exact-SHA release gate不变。
  GitHub Actions provider由ADR-0007固定，profile由ADR-0017重新收敛；origin URL
  与只读访问已验证。exact `5969bfd` run `30322690937`为6/11整体失败并永久
  保留，未被拼接或追认。ADR-0017、T09/T10、同一新SHA的local/Architect/QA
  再资格和六项run/attempt hard gate均已在exact `8318ef1`与run
  `30331336772` attempt 1关闭。
  AEAD nonce reuse、secret leakage、认证前副作用和 task leak 仍是 P0 实现风险，
  其控制合同见 ADR-0002/0004/0005 与 TEST-0001。

## M1 — 完整 TCP 与 TCP 互操作

- **Status:** closed（M1-T01～M1-T04 done；local close gates、三方 close review
  与 exact-SHA hosted qualification PASS）
- **Objective:** 在不复制 transport state machine 的前提下，将 TCP 扩展到
  三个指定方法并完成完整 reference interoperability。
- **Entry conditions:** M0 closed；AES-128 wire/runtime/key lookup contract
  经实测稳定；reference versions 已固定；AES-256/ChaCha primitive source、
  synthetic wire inputs、dependency/profile 与 fixture provenance contract
  由 M1 research/ADR 固定。
- **Exit criteria:**
  1. AES-128、AES-256、ChaCha20-Poly1305 分别通过 KDF/AEAD KAT、SIP022
     TCP 正负向、replay、binding 和 detection-prevention suite。
  2. IPv4、IPv6、domain target、错误地址、目标拒绝、TCP half-close 和
     cancellation/error mapping 行为均有 acceptance-mapped 测试。
  3. `3 methods × 2 reference implementations × 2 directions = 12`
     个 TCP required interop cases 全部通过；required case 不因环境缺失静默跳过。
  4. M0 security、resource、observability、platform smoke 和 host full gate
     回归通过。
- **In-scope tickets:**
  - M1-T01：三方法 crypto profile、primitive fixtures、dependency/lock policy；
  - M1-T02：共享 SIP022 TCP flow 与 IPv4/IPv6/domain target path；
  - M1-T03：method-aware config/binaries 与 local product/lifecycle matrix；
  - M1-T04：12-cell hosted qualification 与 thin CI orchestration。

  Dependency graph：

  ```text
  M1-T01
  ├─ M1-T02 ── M1-T03 ──(integration blocker)── M1-T04
  └─ M1-T04 implementation
  ```

  唯一 initial frontier 是 M1-T01。T01 done 后 T02 与 T04 implementation
  ownership-disjoint；T03 等待 T02；T04 最后集成。
- **Deferred/out of scope:** UDP；M3 最终 native packaging/lifecycle
  qualification；M4 performance/resource gate。
- **Integrated commit:** complete local product/control checkpoint
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef`（包含 M1-T01～M1-T04
  product checkpoint `fba23ca0b628bd6935d0977e3d9df7836b957e78` 与 test-budget
  gate control repair；remote `codex/integration/m1` 精确指向该 SHA）
- **Open blockers and risks:** 当前没有 open canonical root blocker。
  T01 的 clean-target process-test build-order advisory 记录为
  `QA-M1-T01-001`，不阻塞后续工作。T02 的 canonical review root
  `M1-T02-REVIEW-001` 经两次明确的一次性用户授权完成 additional repair 与
  superseding Architect verification 后关闭；原 full/targeted 记录保留。
  T03 exact candidate 的 Architect/QA full review 均 `PASS_WITH_NOTES`；
  Windows 本机 real-process IPv6 row 因 `WSAEACCES` 未执行，且 fixed port 1080
  占用阻断 local platform artifact run，不能计作本机 PASS。exact `874c83d`
  的 hosted run `30367147537` attempt 1 已补齐 quality、MSRV、Windows MSVC、
  Linux GNU、Linux musl 与 interop 六项 success；interop raw log 中
  M1-INT-001～012 各一条 PASS。T04 candidate 的 Architect/QA full review 均
  PASS，local/pure 与 hosted release evidence 均已产生且没有跨 run 拼接。
  close gate 首次 test-budget 运行真实暴露脚本把 ticket-only delta allowance
  错用于 milestone；control commit `81345fbb56ac4cdbf1aea3a3f020d6fd514b187f`
  仅恢复 TEST-0002 已批准语义。final exact SHA `874c83d` 上 66 项 workflow tests、
  authoritative full 与 milestone ratchet 均 PASS；ratio `2.041`，required
  `2.042`，没有预算豁免。三方 close review 接受后，ratchet baseline 以
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 为来源更新为
  code `7720`、tests `15759`、ratio `2.041321`。
  execute 风险是 method/profile 错配、partial address-family conversion、fixture
  provenance/rights、hot-path allocation/dispatch 与 hosted provider availability；
  ADR-0018/0019、TEST-0002、exact-SHA review 和 fail-closed release gate 已给出
  控制。一次性 remote qualification scope 已消费并撤销；任何 rerun、第二次
  push、remote `master`、PR、tag、release 或 publish 仍需另行授权。
- **Closeout:** 2026-07-28 close gate 在 docs-only source
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 启动。Product Manager、
  Architect 和 QA 均 `PASS_WITH_NOTES`，没有 blocker/major finding 或 product
  repair。Team Lead 在 exact product/release SHA `874c83d` 重跑 binary build、
  authoritative full 4/4、`git diff --check` 与 milestone ratchet，全部 exit 0。
  authenticated quality raw log 中 real-process matrix test 恰出现一次，IPv6
  conditional skip marker 为零次；Windows 本机未执行记录没有被改写成本机 PASS。
  durable handoff 为 `docs/handoffs/HANDOFF-M1-2026-07-28.md`。

## M2 — 完整 UDP 协议纵切与 UDP 互操作

- **Status:** closed
- **Objective:** 通过 protocol API 和 server direct UDP path 交付三个方法的
  SIP022 UDP，不新增 SOCKS5 `UDP ASSOCIATE` 等公开 inbound。
- **Entry conditions:** 已满足。M1 closed；shared method/key/address contracts
  稳定；ADR-0020～0022 Accepted，SPEC/TEST-0003 Approved。
- **Exit criteria:**
  1. 三个方法通过 reviewed primitive/composite UDP fixtures、header/address/
     65,507 bounds、tamper/truncation、timestamp、binding 和 semantic failures。
  2. session ID、fresh ChaCha nonce 和 per-direction monotonic packet ID 不造成
     AEAD key/nonce pair reuse；counter exhaustion fail closed。
  3. 8,129-value per-direction replay window 只在 authentication、完整 semantics
     和 capacity reservation 后原子 recheck/commit。
  4. Server 按 authenticated client session ID 路由并支持 validated roaming；
     client current+old associations、generation binding和state至少保留60秒。
  5. session/allocated bytes/depth-4 queues/idle/resolution均执行冻结上限；
     saturation、并发expiry、timeout/cancel/shutdown不泄漏或驱逐active state。
  6. server same-port TCP+UDP atomic bind、offline config、closed telemetry和
     三方法protocol-API→direct UDP local echo通过；TCP-only compatibility回归。
  7. `M2-UDP-INT-001..012` 在同一authorized exact SHA/run/attempt取得
     12/12+cleanup，缺失/unavailable不得waive。
  8. M0/M1回归、test-budget ratchet、MSRV/三平台和`workflow.toml` full通过。
- **In-scope tickets:** M2-T01～M2-T06 均已 `done` 并完成本地 integration。
  M2-T05 hosted/platform qualification 首轮在 superseded SHA `a168b89`
  失败；随后保留该失败历史，修复并在 exact
  `52d1610a127349e7a817a67c81c77e0383d20d1e` 的同一
  push-triggered run/attempt 完成 TCP/UDP qualification。M2-T06 再以
  deterministic focused IPv6 row 关闭 M2-AC-06 的最后证据缺口，并在最终
  exact `7907cda05a56e1c3b85af2dd8faeb85a385154b7` 重跑全部六项 hosted
  results。
  Initial implementation frontier 为
  M2-T01 + M2-T03：

  ```text
  M2-T01 crypto ───────┐
                       ├─ M2-T02 protocol/replay ─┬─ M2-T04 composition
  M2-T03 core/runtime ─┘                          └─ M2-T05 qualification impl
                                                    │
  M2-T04 ───────────── T05 integration/release ─────┘
  ```

  Wave 1 exact product integration
  `0dff5c104149e7042f5e62dc10831f208a0e16ad` 通过 authoritative quick
  3/3、full 4/4、combined ticket-budget、workflow validation 和 exact-SHA
  Architect/QA integration gates；三个 review root findings 均由一次各票
  bounded repair 关闭，无 accepted debt，未 push/publish。

  Wave 2 exact product integration
  `6e54cce52e5e29135acd91f6337a4516a094852e` 通过 authoritative quick
  3/3、full 4/4、ticket-budget、workflow validation 和 exact-SHA
  Architect/QA integration gates。`ARCH-M2-T02-001` 由一次 bounded repair
  关闭；`QA-M2-T02-N01` 作为 nonblocking debt 要求 T04 证明 request/response
  protocol commit 均位于 T03 reserved closure 内。未 push/publish。

  Wave 3 T04 exact product integration
  `980540bd439c438eb196cbc3096cbea0cda3fb4d` 通过binary build、
  authoritative quick 3/3、full 4/4、focused/workspace all-features
  100-cycle、ticket-budget、workflow validation和exact-SHA Architect/QA
  integration gates。`M2-T04-REVIEW-001`由一次substantive repair关闭；
  `M2-T04-INTEGRATION-001`由不消耗substantive budget的mechanical
  TCP-only fixture isolation关闭；`QA-M2-T02-N01`已满足。该 Windows
  T04 worktree 的 IPv6 row 历史状态仍为 **NOT EXECUTED**；M2-T06 后续在
  exact-SHA Linux quality job 实际执行并关闭 `ARCH-M2-T04-N01` /
  `QA-M2-T04-N01`，没有把 Windows 结果改写为 PASS。

  Wave 4 T05 exact product integration
  `90c173f014f84761ee485ec584b7aa3fe8e7abab` 包含initial、first repair
  和user-authorized superseding repair。`bc589ee`恢复ADR-0014规定的
  forward equality、reverse equality、application write shutdown、
  target EOF/shutdown、application EOF顺序，并保留同一current-SHA run的
  12 TCP + 12 UDP fixed plans、provider continuation、transport summaries
  和fail-closed cleanup。Architect/QA superseding reviews均`PASS`，
  `M2-T05-REVIEW-001`已关闭；原full/targeted `ESCALATE`记录保留。
  User-authorized workflow-control commit `dff012a`经Architect/QA
  `PASS`，只允许处置targeted escalation中冻结的blocking IDs并继续执行
  canonical root、active repaired SHA、separate repair override和per-reviewer
  single-use review authorization约束。Exact integration quick 3/3、full
  4/4、focused qualification 12/12、ticket/milestone budgets和final
  Architect/QA integration gates均通过；QA仅记录nonblocking
  `M2-INT-QA-001`。

  首次authorized M2 hosted run `30408245840` attempt 1在exact
  `a168b89eb8dcd0c7a06df06b95a57d63893f2ab6`通过quality、MSRV、
  Windows、Linux GNU/musl和两个provider setup；UDP为`12/12`，TCP为
  `9/12`。SingBox reference-client的`M1-INT-003/007/011`因
  `ApplicationCleanEof`早于target EOF/shutdown evidence而失败，旧run保持
  FAIL且未rerun/splice。Exact local repair `0395d7df`恢复bounded
  target-shutdown/application-acknowledgement edge；repair-base budget
  `0/120`、original-base `1086/1144`均PASS，qualification contract
  `13/13`。QA exact-SHA verification `PASS`，Architect
  `PASS_WITH_NOTES`，仅保留100 ms scheduler-bound advisory。

  为保留既有legacy review history，append-only root-cycle control
  `f95b821f`及唯一修复`6bc85d65`已集成。Initial Architect
  `BLOCK`的`ARCH-M2-T04-001/002`经targeted re-review均RESOLVED；
  focused root-cycle `5/5`、full workflow `73/73`、Architect/QA repair
  gates均PASS。Preliminary local product/control checkpoint为
  `6a4e35062bd6d1631a029230e7cffdc3ba0f7db6`。

  T05 qualification assembly
  `52d1610a127349e7a817a67c81c77e0383d20d1e`通过serialized authoritative
  quick `3/3`、full `4/4`、workspace binary build、qualification contract
  `13/13`、workflow `73/73`、policy `17/17`、ticket/milestone budgets以及
  exact-SHA final Architect/QA assembly gates。Separate exact remote scope
  `m2-20260729-remote-qualification-52d1610-a1`随后仅允许fast-forward push到
  `origin/codex/integration/m2`并观察其一次push run；该scope在push前消费
  `1/1`并自动撤销。

  GitHub Actions run `30415717152`, attempt `1`, event `push`在同一SHA完成
  `success`。六项expected jobs `quality`、`msrv`、Windows MSVC、Linux GNU、
  Linux musl与`interop`全部success；interop raw log明确记录
  `provider_setup sing_box=0 shadowsocks_rust=0`、TCP `12/12` +
  `cleanup=PASS`以及UDP `12/12` + `cleanup=PASS`，两个summary均绑定相同
  SHA/run/attempt。没有rerun、`workflow_dispatch`、`master` push、PR、tag、
  release、publication、ref deletion或其他remote mutation。

  M2 close evidence assembly
  `7907cda05a56e1c3b85af2dd8faeb85a385154b7`在上述 product/control
  lineage 上增加 user-authorized root-cycle control
  `dd646ae861a105ee104425fdb327100209fe1b3c`、唯一 bounded repair
  `9528679a89853fe7df62b368c6b84c585c811071`，以及 reviewed T06 evidence
  candidate `d1c12627632112826fe3dee884caf5facb291e48`。Control workflow
  `75/75`、qualification contract `13/13`、policy `17/17`、authoritative
  quick `3/3`、full `4/4`、ticket/milestone budgets 和 final exact-SHA
  Architect/QA assembly gates均PASS。

  Separate single-use remote scope
  `m2-20260729-remote-qualification-7907cda-a1`仅允许把该 exact SHA
  fast-forward push 到 `origin/codex/integration/m2`并观察其一次 push run；
  scope 在 push 前消费 `1/1`并自动撤销。GitHub Actions
  [run `30425476328` attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30425476328)
  在同一 SHA 完成 `success`，六项 expected jobs 全部 success。Quality raw
  log 中 focused IPv4-ingress→IPv6-direct-target row 恰执行一次，结果为
  `1 passed; 0 ignored`；三报文 payload/source/cleanup marker 与 exact
  SHA/run/attempt completion marker 各出现一次。Interop raw log 记录两个
  provider setup 均为 `0`、TCP `12/12` + `cleanup=PASS`、UDP `12/12` +
  `cleanup=PASS`及全零 final status。没有第二次 push、rerun 或其他 remote
  mutation。

- **Deferred/out of scope:** public client UDP inbound、SOCKS5 UDP ASSOCIATE、
  SIP023/multi-user、routing/DNS proxy/custom resolver、M3 platform/lifecycle
  qualification和M4 performance。
- **Integrated commit:** reviewed and remotely qualified product/control
  commit `7907cda05a56e1c3b85af2dd8faeb85a385154b7`；后续 ticket/roadmap/
  CI/handoff/baseline closeout commit 仅存在于本地，不是另一个 remotely
  qualified product SHA。
- **Open blockers and risks:** 当前没有open canonical root；
  `M2-T05-QUALIFICATION-001`已由run `30415717152`解决，
  `M2-CLOSE-IPV6-001`已由run `30425476328`的同SHA/attempt证据解决，六票均
  `done`、runtime phase为空且M2已关闭。`M2-INT-QA-001`仍是parallel
  server-test port/readiness contention的nonblocking advisory；
  `ARCH-M2-T05-HOSTED-N02`的100 ms scheduler bound也保持advisory。只有
  authoritative serialized gate复现或证据指向shipped defect时才建立新root。
  下一入口是 M3 execute；planning没有release/publication或额外remote state。

## M3 — 运维、生命周期与平台资格

- **Status:** closed
- **Objective:** 稳定当前 v0 的合法 schema v1、CLI/error、redacted
  tracing和metric identity；建立不依赖永久产品拓扑的事务式supervisor；
  在三目标native release artifacts上证明bounded process lifecycle和same-SHA
  资格。
- **Entry conditions:**
  - M1、M2 closed，SIP022 TCP/UDP和24-cell interop baseline已有exact-SHA证据；
  - context audit verified，`AGENTS.md`已把已证明 M3 结果移入 current facts，
    `Active planned changes` 为 `None`；
  - ADR-0023/0024 Accepted，SPEC/TEST-0004 Approved；
  - M3-T01～T03、M3-T05～T08均已integrated并为`done`；M3-T04在唯一
    repair与targeted re-review后`deferred`，由T06承接approved replacement
    outcome；
  - exact `d9e59d787c3fe78dfca778ee8a36668a45387368`的same-run hosted
    qualification通过quality、MSRV、Windows、GNU、musl、interop与final
    qualification，两个late evidence roots均resolved；
  - current pinned target triples/toolchains/provider保持authoritative。
- **Exit criteria:**
  1. M3 close时全部client/server合法v1配置形成preserved cohort，在v0.x及
     ADR-0023的successor兼容窗口内继续有效；effective defaults/ranges/method
     widths与version direction有table evidence。
  2. 当前单listen/server、IPv4 operator endpoint、两个binary roots和十member
     workspace只作为current adapters；architecture guards保护dependency/deep
     seams而不穷尽future topology。
  3. `--config/--check-config/--help/--version`、0/1/2 exits、four config codes
     和eight run codes稳定且脱敏；semantic validation严格先于所有resources。
  4. closed JSON trace fields和十四metric family name/type/label/meaning通过
     exact identity/cardinality/secret-destination sentinel gates。
  5. reusable supervisor证明all-root prepare-before-poll、deterministic rollback、
     transitive single ownership、monotonic cancellation/deadlines、flow isolation、
     graceful/forced/reap。
  6. client/server production adapters完成至少100个bounded
     startup/failure/shutdown/restart cycles，TCP half-close和UDP enabled/disabled
     回归通过，owner snapshots/rebind回baseline。
  7. Windows MSVC、Linux GNU、Linux musl release binaries均native执行
     help/version/config/startup rollback/signal shutdown/rebind；artifact
     SHA-256和PE/ELF/GLIBC/musl linkage evidence齐全。
  8. 同一exact integrated SHA/run/attempt上的authoritative full、
     security/process、TCP12/12、UDP12/12、three targets、milestone test budget
     和Architect/QA gates通过，无blocker/major或skipped required row。
- **In-scope tickets:**
  - M3-T01 preserve schema v1 compatibility；
  - M3-T02 stabilize observability contract；
  - M3-T03 build reusable process supervisor；
  - M3-T04 compose transactional binaries（deferred after review escalation）；
  - M3-T06 resolve terminal-root and forced-reap escalation（done）；
  - M3-T05 qualify three native targets（done）；
  - M3-T07 isolate portable UDP lifecycle evidence under parallel execution
    （done）；
  - M3-T08 synchronize terminal UDP test readiness on its causal event
    （done）。
- **Dependency order:** T01/T02/T03 initial parallel frontier → T06 → T05 local
  implementation → T07 first hosted evidence repair → T08 second hosted evidence
  repair → new T05/T07/T08 qualification；
  T06 imports the unintegrated T04 product lineage with a fresh bounded review
  lifecycle；T07 scheduler metadata依赖已done的T06，不把尚未release-done的T05
  写成实现依赖，避免late-repair deadlock。
- **Deferred/out of scope:** multi-inbound/outbound、routing、DNS、Linux
  transparent inbound、Windows TUN、public UDP inbound、SIP023/multi-user、
  hot reload、management API；M4 performance baseline和bounded 10k-idle
  resource qualification；
  archive/installer/signing/upload/publication。
- **Integrated commit:** wave 1 `da8fa58e0f50dda1637e3a2b205e6f34332a5bec`
  integrates M3-T01～T03；exact `ed615cbcd373d882eaa236ee4556d20eb4e16e48`
  integrates M3-T06 on top of material base `938e2b9...`。M3-T04 candidates
  `b35e809...`/`a90c496...` remain unintegrated historical evidence；exact
  `bba40d127dee29a719d6ea1d80fb10427149d890` integrates T05，
  `bc14971c51982b6ad9a970593fb3848b2763b112` integrates T07，and final
  qualified product SHA `d9e59d787c3fe78dfca778ee8a36668a45387368`
  integrates T08。Later coordination-only execute evidence checkpoint
  `d784b06171723bb93fd467cea1a799f58f7d60b0` is the local closeout source and
  is not a separately hosted-qualified product SHA。
- **Open blockers and risks:** none。All wave-1, T05, T06, and late hosted
  evidence findings are resolved under their bounded review histories；
  T04 remains an explicit historical deferral rather than a rewritten PASS。
  Failed runs `30472227257/1` and `30476271774/1` remain immutable evidence；
  fresh run `30494736004/1` at exact `d9e59d78...` passes all seven required
  jobs and resolves `HOSTED-M3-T07-002` without splicing。Pre-close scheduler
  action remains `ready_to_close` because the helper has no separate close
  mutation；durable roadmap/context/handoff state is now `closed`。Close Product
  Manager/Architect/QA verdicts are `PASS_WITH_NOTES`、`PASS_WITH_NOTES`、
  `PASS` with no blocker/major；`ARCH-M3-CLOSE-N01` was a mechanically corrected
  SHA transcription note。M4 performance baseline/bounded 10k-idle resource
  qualification and
  packaging/signing/publication remain deferred by scope。

## M4 — 性能基线、资源与 v0 preview 资格确认

- **Status:** closed
- **Objective:** 在功能和平台 contract 冻结后建立可复现性能基线，并证明同一
  integrated commit 满足全部 v0 preview gates；本里程碑不执行发布。
- **Entry conditions:** 已满足。M3 closed；SPEC/TEST-0005在planning baseline
  `701925681df78ad83076ed67863bf4fecf46f77c`固定`M4-GHA-01`为既有GitHub
  Actions workflow内单个`ubuntu-24.04` hosted `performance` job，并固定
  shadowsocks-rust `1.24.0` asset、toolchain、capacity preflight、config、load、
  warm-up、repetitions与statistics；本机WSL2只作diagnostic。
- **Exit criteria:**
  1. 同机可比配置下，记录 ferrum2 与 shadowsocks-rust 的 loopback aggregate
     TCP throughput、比值和差距；不设阻塞 v0 preview 的最低比值。原始结果仅
     存于runner temp并在输出bounded summary后删除，不提交或上传。
  2. 同一个GitHub-hosted Linux x86_64 runner VM在throughput之后使用release
     client/server建立并保持10,000个end-to-end idle TCP sessions；稳定5分钟后
     每10秒采样一次active owner/task snapshot与两个进程的RSS，共观察30分钟。
     每次 active-owner sample 必须与首个稳定 sample 相同；六个 5 分钟 RSS
     窗口中，每个 binary 的各窗口中位数不得超过首窗口中位数的 105%。关闭全部
     sessions 后 2 分钟内 active owners 必须精确回到加载前、进程仍存活的
     baseline。这是唯一 required resource qualification；不另跑 24 小时、
     多平台或开放时长的 long soak。
  3. 全部 24 个 required interop cases、security/resource suite、三目标
     build/artifact smoke，以及 `docs/agents/milestone-workflow.md` 的全部
     Full validation 命令在同一 integrated commit、同一Actions push
     run/attempt通过。
  4. v0 未决 P0/P1 blocker 为零；已知 debt、deferred scope 和 evidence
      可供 `mode: close` 审核及 handoff。
- **In-scope tickets:**
  - M4-T01：在独立non-shipping `ferrum2-m4-qualification` package内增加唯一
    Cargo-managed、non-default throughput/resource driver与短self-check，并在
    既有workflow增加唯一hosted `performance` job；exact `7730ec7`已`done`；
  - M4-QUALITY-PORT-LOCK-001：只串行该文件五个真实端口/进程测试，关闭run
    `30725843401/1`暴露的既有UDP local E2E released-port并行竞争；exact
    `5f4fed7`已通过WSL、Full和budgets，done；
  - M4-TCP-NODELAY-001：共享accepted-stream与post-connect seam默认启用
    TCP_NODELAY；exact `c0de9bd`已通过focused、Quick、Full和budgets，done；
  - M4-T02：exact `9b379a4` run `30730883667/1`通过全部M4 gates，done。

  Dependency graph：

  ```text
  M4-T01 qualification driver ── M4-T02 exact-SHA qualification ── mode: close
  ```
- **Deferred/out of scope:** SIP023、多用户、公开 UDP inbound、
  multi-inbound/outbound、routing、DNS proxy、multi-upstream、load balancing、
  proxy chaining、Linux transparent inbound、Windows TUN、hot reload、
  management API、reduced-round ChaCha、custom executor 和 `io_uring`。
- **Integrated commit:** M4-T01 exact `7730ec730258971652270cc6ef41be9457abc2a7`；
  local M4-T02 resource repair exact `56aadd4b25baacb6972ed9bf65ae5052a0d4c6a8`；
  remote M4-T02 diagnostic candidate exact `2f4190c272f79c5d90ebb2d70cdade0378e44e02`；
  local M4-T02 RSS diagnostic repair exact `7b63bd588e1be600beb417636ed0d37ac3b0fb44`；
  local M4-T02 WSL target-backlog repair exact
  `7c19e80f7c7fcb68e3c6b3e562c6d01a379ebf47`；
  local M4-T02 paired-RSS diagnostic exact
  `1d3c117231bf5b99641d02b43b6579359c938644`；
  paired hosted diagnostic exact `a53a5d7cf8c2506527d3dfa8f74e64898604154d`；
  local selected-profile repair exact `230594544e88ab555e1718ba92721745705b572b`；
  final hosted attempt exact `35fb3f85633ee32ba5909ecbf5d74c4ad4a89f11`；
  local quality repair exact `5f4fed7e0835298fee820ece7b858db45ea34044`；
  accepted hosted qualification exact `9b379a426853d86a184464f6fd8c73081b464535`；
  local closeout descendant exact `a38a1e84c90a7e03c047eaa4e275fc7ed3410cdb`。
- **Open blockers and risks:** blocking P0/P1 issues和blocking review findings为零。
  GitHub-hosted image/hardware会滚动，因此保留实际profile并在同一VM交错比较；
  吞吐比仍仅作诊断。不授权新的remote、package、release或publish动作。

## M5 — `shadowsocks-crypto` 单一密码实现迁移

- **Status:** closed
- **Objective:** 保留`ferrum2-crypto`公开seam、`ferrum2-shadowsocks`状态机、wire和
  schema v1行为，把三种标准SIP022方法完整切换到受控patched
  `shadowsocks-crypto 0.7.0`，并删除本地cipher/KDF实现、无用依赖和任何双实现路径。
- **Entry conditions:** 已满足。M4 closed；planning baseline为
  `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`；上游来源、现有实现边界和可复用
  KAT/negative/interop/performance/MSRV evidence已清点；ADR-0025、SPEC/TEST-0006
  已Accepted/Approved。
- **Exit criteria:**
  1. 产品正常依赖图中仅patched `shadowsocks-crypto`提供SIP022 cipher/KDF；只启用
     `v2`，且没有旧实现、fallback、selector、`v2-extra`或reduced-round。
  2. 显式nonce exhaustion、secret zeroization、既有错误语义与三方法TCP/UDP
     KAT/negative测试全部通过，public seam和protocol sources不变。
  3. 同一exact SHA/run/attempt通过Full、Rust 1.85、许可证/依赖审查、三平台、
     TCP/UDP `24/24`外部互操作及既有M4 performance/resource profile。
  4. Ticket/milestone budget与Architect/QA blocking review通过；任一required gate
     缺失或失败即M5 `blocked`，不得恢复旧backend。
- **In-scope tickets:**
  - M5-T01：固定并最小加固vendored `shadowsocks-crypto`，`done`；
  - M5-T01R：补齐checked raw TCP subkey owner，依赖T01，`done`；
  - M5-T02：原子切换TCP/UDP adapter并删除本地实现，依赖T01R，`done`；
  - M5-T03：在一个accepted exact SHA上完成本地与hosted资格及关闭证据，依赖T02，
    `done`。

  Dependency graph：

  ```text
  M5-T01 pin/harden ── M5-T01R raw owner ── M5-T02 switch/delete ── M5-T03 done
  ```
- **Deferred/out of scope:** protocol state machine替换、SIP023/EIH、多用户、多PSK、
  public UDP inbound、新method、schema/config变化、runtime crypto selection、上游发布、
  新benchmark框架或性能优化。
- **Integrated commit:** accepted exact qualification
  `6ca043460f0a5233a0b39c9931b4f3f3a22f1cba`，tree
  `3474c7896bb8e3042e323991616418c2a93c76b4`，product commit
  `db4f100c35a2fc6615828b9aa176e8ede62eb855`；automatic push run
  [`30743888837/1`](https://github.com/zzffu/ferrum2/actions/runs/30743888837)成功。
- **Open blockers and risks:** blocking findings为零；`QA-T03-001`已关闭。
  Performance ratio仍仅作诊断；TCP auth scratch、UDP opaque prehash与zeroize owner
  经Architect接受为非阻断残余风险。单次push scope已消费撤销；不授权rerun、
  dispatch、second push、PR、package、release或publication。

## M6 — 有界 SOCKS5 UDP ASSOCIATE

- **Status:** closed
- **Objective:** 仅在client显式`[udp]` opt-in时，把SOCKS5 `UDP ASSOCIATE`
  通过现有三方法SIP022 UDP和server direct outbound转发；association、endpoint、
  buffers、queues、idle、tasks和shutdown全部有界，不加入routing。
- **Entry conditions:** 已满足。M5 closed；planning baseline为
  `35354f274847d2608a2009e04aaa3b17fb4fa8f4`；RFC 1928、pinned sing-box与
  shadowsocks-rust行为及现有SOCKS/SIP022/runtime/harness seam已清点；ADR-0026、
  SPEC/TEST-0007已Accepted/Approved。
- **Exit criteria:**
  1. Existing client v1 documents保持UDP disabled和原TCP行为；显式section离线完整
     校验，`enabled=false`拥有zero UDP resources。
  2. Control-owned association、TCP-peer-IP authority、fixed/learned source port、
     `FRAG!=0` silent drop和IPv4/IPv6/domain target通过positive/negative evidence。
  3. 每个association复用一个collision-safe `UdpClientSession`及现有session/byte/
     queue/idle limits；所有close/cancel/shutdown路径返回owner和socket到baseline。
  4. 既有`M2-UDP-INT-001..012`保持ID和矩阵；六个FerrumClient案改用public client
     binary，六个reference-client案继续独立cross-validation。
  5. 一个exact SHA通过Full、Rust 1.85、三native targets、budget、external UDP
     `12/12`+cleanup和blocking review；缺失、失败或未授权即blocked。
- **In-scope tickets:**
  - M6-T01：SOCKS5 command/control与standalone UDP wire interface，`done`；
  - M6-T02：显式opt-in并组合bounded client association，依赖T01，`done`；
  - M6-T03：替换六个FerrumClient evidence adapter并完成资格，依赖T02，`done`；
  - M6-T04：以当前exact ratio建立永久test-budget ceiling，依赖T03，`done`。

  ```text
  M6-T01 SOCKS interface ── M6-T02 client composition ── M6-T03 qualification ── M6-T04 budget
  ```
- **Deferred/out of scope:** fragment reassembly、shared UDP listener、source roaming、
  routing、DNS proxy、multi-upstream/chaining、UDP-over-TCP、SIP023/multi-user、new
  dependency、throughput claim、package/release/publication。
- **Integrated commit:** exact `7f1e45c174e749d3dddd32d187365722cce94dbe`, tree
  `fc2052de743ae5447617b59b06e331f468efd7a3`；automatic push run
  [`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553)。
- **Open blockers and risks:** blocking findings为零。User-authorized close credits
  quality、MSRV、platform `3/3` and interop；performance/dependent aggregate不计入M6且
  不声称PASS。Single push scope已消费；不授权rerun、dispatch、second push、PR、
  package、release或publication。

## M7 — 具名多 inbound/outbound 静态组合

- **Status:** executing
- **Objective:** additive schema v1接受多个有界、具名concrete inbound/outbound；每个
  inbound在离线验证期exact解析一个outbound tag，两个binary复用同一个
  `ProcessSupervisor` transaction原子prepare/rollback，legacy单实例行为不变。
- **Entry conditions:** 已满足。M6 closed；planning baseline为
  `302fd777f4da62a8c1d4d52d81502056f02089c8`；现有config loader、client/server
  composition、shared TCP/UDP state和process transaction已清点；ADR-0027、
  SPEC/TEST-0008已Accepted/Approved。
- **Exit criteria:**
  1. Legacy v1 cohort原样有效；tagged/legacy shape互斥，tag/count/reference/listen graph
     完整离线验证且错误脱敏、zero-resource。
  2. 两个binary支持至少两个inbounds/outbounds、shared outbound和static no-fallback
     mapping；仍是一份process-wide method/PSK，不加入routing。
  3. TCP admission/replay与UDP ID/session/bytes/replay在全部inbounds间保持aggregate
     ownership；server UDP session绑定local inbound并从同一listener回复。
  4. First/middle/last TCP/UDP/metrics failure全部prepare-before-poll并逆序rollback；
     root fatal、signal、forced和restart/rebind返回owner baseline。
  5. 一个exact SHA通过Full、Rust 1.85、三native targets、TCP/UDP各`12/12`+
     cleanup、test budget和blocking review；缺失/失败/未授权即blocked。
- **In-scope tickets:**
  - M7-T01：legacy/tagged config graph与preflight reference validation，`done`；
  - M7-T02：server shared-state TCP/UDP/direct multi-root transaction，依赖T01，`done`；
  - M7-T03：client SOCKS/Shadowsocks static multi-root composition，依赖T02，`done`；
  - M7-T04：real-process、三平台、interop与exact-SHA qualification，依赖T03，`active`。

  ```text
  M7-T01 config -> M7-T02 server risk -> M7-T03 client -> M7-T04 qualification
  ```
- **Deferred/out of scope:** dynamic routing、DNS、multi-upstream groups/load balancing/
  fallback/chaining、per-entry PSK/method、SIP023/multi-user、新adapter kind、Tailscale
  Endpoint、transparent/TUN、hot reload、management API、new dependency、performance
  threshold、package/release/publication。
- **Integrated commit:** M7-T01 exact `f6ee43fa766dd326d33ba140a273b7df201749c1`；M7-T02 exact
  `b864a40a5ada975c09c5b95a1373bd3c15373bdf`；M7-T03 exact
  `b3f7ff8e6dad22d37f8fb95bc42c7e83c6834c72`。
- **Open blockers and risks:** 当前frontier只有M7-T04。Initial candidate `564e11e`的本地
  gates通过，但初审阻塞native driver readiness、direct negative-process evidence和failure
  cleanup；一次bounded repair active。用户明确将T03/T04 budget失败改为recorded/
  nonblocking，最终记录不得声称budget PASS。Remote push/run、PR、tag、release或
  publication均未授权。

## 决策登记

| ID | 状态 | 决策/延期边界 | Contract/evidence |
|---|---|---|---|
| DEC-001 | resolved in M0 plan | official-site SIP022 commit/blob；Rust 1.97.1 build、MSRV 1.85.0、exact dependencies、GPL-3.0-only | `ADR-0001`、upstream baseline |
| DEC-002 | resolved in M0 plan；topology scope clarified in M3 | 十个members是M0 current conformance profile，不是future exhaustive list；one-way DAG、runtime-neutral core contracts和deep-module boundaries继续约束 | `ADR-0001`、`ADR-0023`、`SPEC-0001/0004` |
| DEC-003 | resolved in M0 plan | secret newtypes/capability key provider、future selector seam、separate wall/monotonic clock、OS CSPRNG | `ADR-0002` |
| DEC-004 | resolved in M0 plan | schema v1、strict typed TOML、`--config/--check-config`、0/1/2 exits、redacted error taxonomy | `ADR-0003` |
| DEC-005 | resolved in M0 plan | full-auth/semantic-before-replay ordering、exact 60s/capacity fail-closed、single I/O、zero-linger、binding | `ADR-0004` |
| DEC-006 | resolved in M0 plan；process lifecycle refined in M3 | one owner task、numeric time/buffer caps、half-close/shutdown和closed trace/metric identity；all-root transaction由DEC-029细化 | `ADR-0005`、`ADR-0024` |
| DEC-007 | resolved in M0 plan | sing-box 1.13.14、shadowsocks-rust 1.24.0、asset hashes、unavailable=FAIL/BLOCK、three exact targets | `ADR-0006`、upstream baseline |
| DEC-008 | resolved in M2 plan | bounded UDP protocol API；8,129-value window；client current+old；session 4,096、16 MiB allocated bytes、depth-4 queues、65,507 wire、300s idle；expired-oldest-or-reject eviction | `ADR-0020`～`ADR-0022`、SPEC/TEST-0003 |
| DEC-009 | resolved in M3 plan | 保留M0 fixed triples/provider；M3增加native release-artifact config/lifecycle/linkage/hash，不要求archive/installer/publication format | `ADR-0006`、`SPEC/TEST-0004`、M3-T05 |
| DEC-010 | resolved in M4 plan | `M4-GHA-01`固定为既有GitHub Actions workflow中的单个GitHub-hosted `ubuntu-24.04` x64 `performance` job，要求至少4 logical CPUs/15,000,000 KiB RAM、Rust 1.97.1、记录滚动image/hardware identity；AES-128 TCP、8 streams、64 KiB、10s warm-up+30s measure、每端5次固定交错median；比值无最低门；同job resource唯一门为5分钟稳定+30分钟10k idle/10秒采样、active/fd/task恒定、六个RSS median≤首窗105%、2分钟exact drain；本机WSL2仅diagnostic | `SPEC-0005`、`TEST-0005`、M4-T01/T02；historical 90%/long-soak及本机资格文字不再是current contract |
| DEC-011 | resolved in M0 CI amendment | GitHub Actions required provider；`.github/workflows/m0.yml`；fixed hosted runners/jobs/security/evidence；本机 WSL2仅作诊断 | `ADR-0007`、`SPEC-0001`、`TEST-0001`、M0-T08 |
| DEC-012 | resolved in M0 narrow amendment | fixed `aes 0.9.1`/`ghash 0.6.0` no-default `zeroize` direct feature anchors，使 `aes`/`ghash`/`polyval` keyed state drop-zeroize；exact resolved feature/package-ID 与 110-tuple lock identity evidence；无版本/wire/API/scope变化 | `ADR-0009`、`ADR-0002`、M0-T01/M0-T02 |
| DEC-013 | resolved in M0 narrow amendment | opaque unsplit SIP022 flow、configured-server/application-target separation、core `Session.initial_payload` ownership、executor-neutral polling、direction-local normal close、single fatal arbitration与binary-local Tokio adapters；无wire/product/core/runtime/manifest变化 | `ADR-0010`、`SPEC-0001`、`TEST-0001`、M0-T03/M0-T07 |
| DEC-014 | resolved in M0 narrow amendment | lifecycle采用black-box child/port/temp + T06 direct counters + production-used binary-private registry composition三段证据；native detection由harness primitive-only current-time generator精确构造47案，只允许两个test dev edges与唯一lock hunk | `ADR-0011`、`SPEC-0001`、`TEST-0001`、M0-T07 |
| DEC-015 | resolved in M0 narrow amendment | opaque configured-server connect capability分离validated configured connect与fresh request-first-write deadlines（默认10秒/5秒，禁止hardcode）；runtime relay failure保留direction-separated partial stats，server prefix loop在binary-private composition内保持progress/cancel/accounting | `ADR-0012`、`SPEC-0001`、`TEST-0001`、M0-T03/M0-T06/M0-T07 |
| DEC-016 | resolved in M0 narrow amendment | 两个binary各增加一个workspace-inherited、dev-only Tokio `test-util` edge以运行paused-time composition tests；root/normal/production graph、version与lock不变 | `ADR-0013`、`SPEC-0001`、`TEST-0001`、M0-T01/M0-T07 |
| DEC-017 | resolved in M0 narrow amendment | external四案先比较pre-FIN双向各16386-byte distinct payload，再观察ordered clean-EOF convergence且不声明target-FIN causality；peer FIN后新reverse drain继续由同一SHA的M0-E2E-001/M0-LIFE-003独立blocking；pin/wire/product不变 | `ADR-0014`、`SPEC-0001`、`TEST-0001`、M0-T08 |
| DEC-018 | resolved in M0 hosted-rebind amendment | client/server listener仅在Unix bind前启用reuse-address，Windows保持default且禁止reuse-port；harness首次listener与exact probe镜像同策略bind+listen并保留live-owner collision；新增唯一既有pin的`socket2` dev edge；四类hosted evidence-script portability缺陷fail closed修复 | `ADR-0015`、`SPEC-0001`、`TEST-0001`、M0-T07/M0-T08 |
| DEC-019 | resolved in M0 invariant/evidence amendment | 产品/安全/release outcome为normative invariant；具体fixture/probe/test-only edge为selected conformance profile，可在执行前以等强、可审计、single-writer方式替换；机械修复不再自动要求新产品ADR | `ADR-0016` Accepted、`SPEC-0001`/`TEST-0001` amendments Approved、M0-T01/T02/T03/T06/T07/T08 |
| DEC-020 | resolved in M0 CI convergence | qualification保留在Cargo compile/lint policy内但本机不执行external entry；hosted profile收敛为quality、MSRV、三平台matrix与一个四案interop，共六项result；删除11-job/self-audit/filter/link-help机械合同 | `ADR-0017` Accepted、`SPEC-0001`/`TEST-0001` amendments Approved、M0-T09/T10 done；exact `8318ef1` run `30331336772`六项success |
| DEC-021 | resolved in M1 plan | method-bound secret/profile；AES-128 为16-byte、AES-256/ChaCha为32-byte；AEAD owner内分派且TCP state machine唯一；ChaCha 32-byte width显式标为compatibility interpretation | `ADR-0018`、M1 research、SPEC/TEST-0002 |
| DEC-022 | resolved in M1 plan | target支持IPv4/IPv6/1～255-byte ASCII domain；system resolution最多16 candidates并与全部sequential dial共用absolute deadline；endpoint/reply端到端使用`SocketAddr` | `ADR-0019`、SPEC/TEST-0002 |
| DEC-023 | resolved in M1 plan | 保留两个reference pins与thin hosted profile；固定M1-INT-001～012，12/12+cleanup且同一exact SHA/run/attempt才PASS | `SPEC-0002`、`TEST-0002`、M1-T04 |
| DEC-024 | resolved in M2 plan | canonical `MethodProfile` + `TcpMethodProfile` alias；AES UDP separate header/session key与ChaCha direct-PSK XChaCha capability均留在crypto deep module | `ADR-0020`、M2 research、M2-T01 |
| DEC-025 | resolved in M2 plan | server只按authenticated client session ID；valid roaming；current+old两association；8,128-lag atomic replay与generation-bound response | `ADR-0021`、M2-T02 |
| DEC-026 | resolved in M2 plan | minimal core datagram value；generic runtime ownership；`server.listen`同端口TCP+UDP且default enabled；双bind transaction和closed UDP telemetry | `ADR-0022`、M2-T03/T04 |
| DEC-027 | resolved in M2 plan | 固定M2-UDP-INT-001～012；ferrum direction用Cargo example black-box adapter；每案同session三datagrams，12/12+cleanup/exact SHA/run/attempt | `SPEC-0003`、`TEST-0003`、M2-T05 |
| DEC-028 | resolved in M3 plan | M3合法v1 config preserved cohort；all v0.x + successor后12个月且2 stable minors + prior notice；optional/widening v1或explicit new schema；no heuristic fallback；current topology不永久冻结 | `ADR-0023`、SPEC/TEST-0004、M3-T01/T02/T04/T06 |
| DEC-029 | resolved in M3 plan | topology-neutral Validated→Prepare→Active→Quiesce/Drain→Stop outcome；all-root prepare、rollback、single transitive ownership、monotonic cancel/deadline、grace/force/reap | `ADR-0024`、SPEC/TEST-0004、M3-T03/T04/T06 |
| DEC-030 | resolved in M3 plan | 同一exact SHA的Windows MSVC/Linux GNU/Linux musl release binaries native config/lifecycle、SHA-256及PE/ELF/GLIBC/musl linkage；unavailable=BLOCKED；无packaging/publication | `SPEC/TEST-0004`、M3-T05 |
| DEC-031 | resolved in M3 execute escalation | terminal UDP root先immediate local force/join/reap再返回original fatal；operator仍使用一个configured absolute grace；`Forced`后固定5秒cleanup watchdog，触发即explicit `shutdown.cleanup`且不覆盖primary cause；internal claims用production-used direct composition，OS/process claims用black-box，无product injection surface | User-confirmed solution A、`AUTH-M3-T06-001`、`ADR-0016/0024`、SPEC/TEST-0004、M3-T06 |
| DEC-032 | resolved in M5 plan | 精确vendor并受控patch `shadowsocks-crypto 0.7.0`；产品仅启用`v2`，保留公开crypto seam和protocol state machines；patch只承载checked nonce、zeroization、AES-UDP header与selected-v2收敛；完成后删除旧实现且不留fallback | `ADR-0025`、M5 research、SPEC/TEST-0006、M5-T01/T02/T03 |
| DEC-033 | resolved in M6 plan | client `[udp]`为schema v1显式opt-in；每个TCP control拥有两个per-association UDP sockets；TCP peer IP权威，非零hint port固定、零port首个valid datagram锁定，地址hint仅advisory；response使用borrowed-authenticate→reserve→materialize/commit；runtime只公开既有per-handle idle/cancel操作；不实现fragment/routing/shared listener | `ADR-0026`、M6 research、SPEC/TEST-0007、M6-T01/T02 |
| DEC-034 | resolved in M6 plan | 按ADR-0016等强替换既有M2证据adapter：保留12个ID/method/reference和six reference-client rows，仅把six FerrumClient rows从protocol example换成显式UDP client binary；不新增provider/matrix/workflow job | `ADR-0016`、`TEST-0007`、M6-T03 |
| DEC-035 | resolved in M7 plan | additive v1 tagged/legacy互斥shape；inbound/outbound全局唯一且有界tag、静态inbound→outbound引用、全部outbound被引用；保留process-wide method/PSK及aggregate TCP/UDP owners；复用`ProcessSupervisor` transaction且不创建`Endpoint` interface | `ADR-0027`、SPEC/TEST-0008、M7-T01～T04 |

## 风险登记

| 风险 | 等级 | 最早控制点 | 控制方式 |
|---|---|---|---|
| SIP022/AEAD/nonce/replay 实现错误 | P0 | M0 | approved ADR/spec、KAT、负向测试、双向互操作 |
| AEAD expanded key/GHASH state 未启用上游 drop-zeroize | P0 | M0 | ADR-0009 exact feature anchors、metadata/package-ID/lock-identity policy、Cargo tree、T01/T02与integration双 gate |
| 认证前 connect/allocate/mutate | P0 | M0 | explicit connector/allocation/state test seams |
| secret 泄漏、destination 成为 metric label 或 cardinality 爆炸 | P0 | M0 | secret types、redaction tests、fixed labels |
| task/session leak、unbounded queue 或错误 half-close | P0 | M0 | owner/termination contract、bounded lifecycle tests；单主机bounded 10k-idle qualification留M4 |
| 外部实现/fixture/version/license 漂移 | P1 | M0 | pin/checksum/provenance 和 required-job policy |
| musl/Windows 差异发现过晚 | P1 | M0 | early build smoke，M3 full qualification |
| GitHub-hosted image weekly drift 或 provider outage | P1 | M0 | fixed OS labels、ImageOS/ImageVersion与toolchain版本用于追溯、unavailable=FAIL/BLOCK；不把Included Software URL形状当控制，也不宣称M3资格 |
| Linux真实流量后listener exact地址无法立即restart，或reuse策略意外允许live-owner共享 | P0 | M0 | ADR-0015 Unix-only reuse/default Windows、禁止SO_REUSEPORT、same-policy bind+listen与live-owner negative、100-cycle gate |
| “等价证据”被事后用作waiver或缩减coverage | P0 | M0 | ADR-0016要求执行前mapping、old/new claim、独立性/failure modes、exact candidate SHA与Architect/QA gate；旧失败不可追认 |
| 三方法 profile/key/salt width 错配或复制 TCP security state | P0 | M1 | ADR-0018 method-bound capability、one shared flow、profile table KAT/negative/interop |
| IPv6/domain partial conversion、认证前 resolution/dial 或 deadline reset | P0 | M1 | ADR-0019 normalized target、zero-side-effect recording table、16-candidate/single-deadline paused-time gate |
| 12-cell qualification 缺案、setup failure短路或不同SHA evidence拼接 | P0 | M1 | 固定case IDs、failure continuation、12/12+cleanup、同一run/attempt exact-SHA gate |
| AES separate-header或ChaCha XChaCha UDP envelope/key/nonce错误 | P0 | M2 | ADR-0020 opaque capability、primary primitive+independent composite fixtures、双向interop |
| replay/association在完整校验或capacity前mutation，或source address错作identity | P0 | M2 | ADR-0021 8,129-window、current+old、serialized recheck/commit、roaming/generation tables |
| UDP session/allocated bytes/queue/accounting泄漏或active eviction | P0 | M2 | ADR-0022 numeric permits、fake-handler saturation/expiry/concurrency、owner snapshots |
| TCP+UDP partial bind或12案UDP false PASS | P0 | M2 | atomic startup/rollback；fixed IDs、black-box example、failure continuation、exact-SHA 12/12+cleanup |
| v1 compatibility被fixture缩窄，或current topology被误冻成永久schema | P0 | M3 | ADR-0023 parser-accepted cohort、compatibility window、non-exhaustive architecture guard |
| fallible roots partial activation、double owner或shutdown cleanup假成功 | P0 | M3 | ADR-0024 prepare-before-poll、failure-position rollback、owner snapshots、100-cycle process gate |
| native artifact未执行、linkage/hash缺失或不同SHA evidence拼接 | P0 | M3 | direct native release observations、PE/ELF/GLIBC/musl records、one exact-SHA summary、unavailable=BLOCKED |
| M3 test-only增长超过ratchet | P1 | M3 | reuse existing tables/harness；ticket delta allowance 120；milestone budget gate |
| benchmark 不等价或噪声驱动错误优化 | P1 | M4 | SPEC/TEST-0005 fixed hosted job/config、同runner交错五次median、记录image/hardware且ratio不阻塞preview |
| 上游TCP nonce wrap、secret-bearing KDF临时值或AES-UDP header边界破坏既有安全语义 | P0 | M5 | exact vendored delta、checked operation/zeroize/header patch、三方法KAT/negative与双向interop；任一失败即blocked |
| dependency feature漂移、reduced-round或旧backend形成双实现 | P0 | M5 | exact no-default `v2` edge、metadata/workspace-policy guard、删除旧实现/依赖、license/MSRV review与single-backend source guard |
| SOCKS UDP变成open/spoofable relay，或invalid/fragment/wrong-source datagram抢占endpoint state | P0 | M6 | control TCP peer IP authority、per-association relay socket、fixed/first-valid port pin、connected upstream、silent-drop/no-mutation tables |
| client UDP session-ID collision、buffer/queue/task/socket泄漏或shutdown假完成 | P0 | M6 | live-ID registry、existing bounded manager、supervised lexical ownership、capacity-before-commit与control/idle/cancel/forced/rebind snapshots |
| duplicate/dangling tag、runtime lookup或silent fallback把配置错误变成partial service | P0 | M7 | config module离线解析完整graph；unique/count/reference/unreferenced negatives；binary只消费resolved concrete context |
| 多listener把TCP/UDP限额乘倍、跨listener replay/session迁移或response从错误listener发出 | P0 | M7 | aggregate admission/replay/session/byte owners；server UDP local-inbound binding；cross-listener negative与owner snapshot |
| 任一后置listener失败时早期root已服务或资源未rollback | P0 | M7 | existing `ProcessSupervisor` prepare-all transaction；first/middle/last TCP/UDP/metrics failure和exact rebind table |

## 决策与范围变更日志

| Date | Milestone | Change | Reason | Evidence |
|---|---|---|---|---|
| 2026-07-27 | Bootstrap | 采用 M0→M4 的纵向路线，不扩大 v0 范围 | 尽早验证最高安全、互操作、平台和性能风险，同时保持每阶段可独立验收 | `AGENTS.md`、`workflow.toml`、仓库清点、Product/Architect/QA bootstrap reports |
| 2026-07-27 | M0 | 首个 plan 目标确定为 AES-128-GCM TCP 安全纵切 | 比纯 workspace scaffolding 更早产生可观察用户路径并验证 module seams | Product PASS_WITH_ACTIONS；Architect/QA 要求安全、生命周期、互操作和平台门前移 |
| 2026-07-27 | M0 plan | M0 改为 `planned`，接受 ADR-0001～0006、SPEC/TEST-0001 与 T01～T08 DAG | DEC-001～007 已有可实现、可测试、ownership-disjoint contract；唯一 initial frontier 为 T01 | Product/Architect/QA plan reports；upstream baseline；workflow validate/frontier/next |
| 2026-07-27 | M0 CI amendment | 以 GitHub Actions/GitHub-hosted runners 取代本机 WSL2 作为 M0 required CI；新增 ADR-0007 和 T08 的唯一 workflow ownership | 绑定 pushed exact integration commit，固定 native runners、11 job、安全与 provider-native evidence，同时不扩大产品/协议范围 | Product/Architect/QA amendment reports；GitHub official runner/security docs；workflow validate/frontier/next |
| 2026-07-27 | M0 duplex contract amendment | 接受opaque unsplit SIP022 flow取代T03 caller-managed transitions，同时分离configured SS server/application target、保留core Session initial-payload ownership与未修改runtime lifecycle | initial candidate无法并发duplex、丢失cipher/payload、拒绝合法fragmentation且无法证明scratch/fatal ownership；用户已授权本地窄blocker修复 | ADR-0010 Accepted；Product/Architect/QA PASS；workflow validate/diff-check |
| 2026-07-27 | M0 evidence/phase contract amendment | 接受组合式lifecycle evidence、primitive-only 47-case native probes、opaque configured connect/first-write phases与failure-preserving relay stats；T03/T06窄reopen，T07保留partial checkpoint并blocked | T07真实composition证明原黑盒/fixture/fused-open/error-only seams无法满足已批准AC；修订不扩大wire/product/operator API/remote范围 | ADR-0011/0012 Accepted；SPEC/TEST amendments Approved；Product/Architect/QA final PASS；workflow validate/diff-check |
| 2026-07-27 | M0 external half-close evidence amendment | 接受：保留sing-box 1.13.14 pin与四项hard gate，把external evidence细化为pre-FIN双向完整bytes及ordered clean-EOF convergence，不声称target-FIN causality；ferrum FIN后reverse drain仍由local/runtime同SHA硬门证明 | exact diagnosis隔离出sing-box 1.13.14在peer FIN后关闭leg的第三方限制；不改变wire/product/API/pin/remote范围 | ADR-0014 Accepted；SPEC/TEST Approved；`f757b58` final Product/Architect/QA PASS |
| 2026-07-27 | M0 binary paused-time contract amendment | 接受两个binary-local exact Tokio `test-util` dev edges与zero-additional-lock-delta policy；不改root/normal/production graph | ADR-0012要求targeted binary paused-time tests，但现有manifest ownership使其无法编译；root/normal/injection/real-time替代均更广或更弱 | ADR-0013 Accepted；勘误base `24ddecf`的Product/Architect/QA final gates均PASS |
| 2026-07-28 | M0 hosted-rebind/evidence portability amendment | 接受Unix-only listener reuse、default Windows、same-policy exact bind+listen及唯一`socket2` harness edge；T08只修正两处full-name exact filters与三个platform linker probes | exact `51fb7327`的run `30301746374`及独立WSL复现把9个failed jobs归约为Linux rebind及四类CI evidence defects；不改变wire/product/API/config/job matrix/remote授权 | ADR-0015 Accepted；SPEC/TEST amendments Approved；Product/Architect/two QA document gates PASS；workflow validate/diff-check |
| 2026-07-28 | M0 invariant/evidence contract amendment | 接受三层合同与执行前equivalent substitution；T01 ownership改为single-writer默认协调，事实性provenance勘误与机械evidence修复不再自动需要产品ADR | 历史ADR-0008/0011/0013/0014/0015证明写死的来源、probe、test edge或第三方时序会形成非产品blocker；不改变任何wire/security/product/platform/job/exact-SHA gate | ADR-0016 Accepted；SPEC/TEST amendments Approved；proposal `a389aa9`的Product/Architect/QA exact-SHA document gates均PASS |
| 2026-07-28 | M0 CI evidence convergence | 接受Cargo-managed non-test qualification及四个job definitions/六个rendered results直接证明quality、MSRV、三平台与四案interop；本机编译/lint但不执行external entry；删除scope self-audit、filter/count、link-help及重复jobs | exact `5969bfd` run `30322690937`的6/11、5 failure再次证明mechanical realization被误当release invariant；不改变wire/security/platform/reference/exact-SHA结果 | ADR-0017 Accepted；SPEC/TEST amendments Approved；M0-T09/T10 done；exact `8318ef1`的local/review gates及run `30331336772`六项success |
| 2026-07-28 | M1 plan | M1 改为 `planned`；接受method-bound三方法profile与完整target/resolution contract，批准SPEC/TEST-0002及四票DAG | M0已关闭；current code仍AES-128/IPv4 hard-code且qualification仅4案，需要先冻结width/address/deadline/fixture/12-cell evidence，避免Engineer临场安全决策 | Product/Architect/QA planning reports；ADR-0018/0019；M1 research；workflow validate/test-budget/frontier/next |
| 2026-07-28 | M2 plan | M2改为`planned`；接受method-bound UDP envelope、8,129-value replay/current+old association和bounded direct runtime；批准SPEC/TEST-0003及五票DAG | M1已关闭；current code/runtime/server/qualification均TCP-only，需要在execute前冻结crypto分歧、mutation ordering、数值limits、same-port startup和12-cell black-box evidence | Product/Architect/QA planning reports；ADR-0020～0022；M2 research；workflow validate/test-budget/frontier/next |
| 2026-07-29 | M2 close | M2 改为 `closed`；六票完成，接受 exact `7907cda` 的本地 full、三平台、TCP/UDP 各 12/12 和 focused IPv6 UDP real-process 证据 | `M2-CLOSE-IPV6-001`已由唯一授权 push run `30425476328/1`关闭；三位 close reviewer 无 blocker/major，且没有扩大 public UDP inbound 或其他 v0 scope | Product/Architect/QA close reports；run `30425476328` raw logs；workflow validate/test-budget/status/next；M2 handoff |
| 2026-07-29 | M3 plan | M3改为`planned`；接受v1 preserved-cohort/evolvable-topology与transactional supervisor两项ADR，批准SPEC/TEST-0004及五票DAG | M2已关闭；current operator contract分散、run cause丢失、binary-local root coordination有partial activation risk，且三目标只有早期build/config smoke；两ADR是最小hard-to-reverse集合 | Context audit；Product/Architect/QA PASS；ADR-0023/0024；workflow validate/context-check/test-budget/frontier/next |
| 2026-07-29 | M3 T04 escalation replacement | T04在唯一full/repair/targeted lifecycle后deferred；新建T06承接完整composition outcome，固定terminal UDP local reap与post-Forced 5秒cleanup watchdog，并把internal与black-box evidence按ADR-0016重映射；T05依赖改指T06 | T04的UDP fatal/Forced circular wait与unresponsive-root无bound在原review budget内未关闭；用户确认solution A并一次性授权local T06，不授权remote/T05/publish/control-plane | Product Manager PASS；Architect design PASS；`AUTH-M3-T06-001` consumed/revoked；T04 `b35e809...`/`a90c496...` retained but not integrated |
| 2026-07-29 | M3 T06 integration | exact `ed615cb...` fast-forward integrated T06；terminal UDP immediate local reap、fixed post-Forced 5s watchdog、portable IPv4 admitted-UDP signal lifecycle与collision-safe/fail-fast fixtures通过 | initial `24561cf...` full reviews发现portable black-box evidence gap；唯一repair关闭canonical `ARC-M3-T06-001`及`QA-M3-T06-001`，不扩展product surface | Architect/QA full BLOCK then targeted PASS；quick `5/5`、full `6/6`、ticket budget/control/diff PASS；no push/publish |
| 2026-07-30 | M3 T05/T07/T08 qualification | exact `d9e59d78...` integrates native qualification and two narrow late evidence repairs；run `30494736004/1`同SHA通过quality、MSRV、Windows、GNU、musl、interop与final qualification；三票done，M3 ready to close | 两个失败run保留且不拼接；T07隔离process-global child baseline，T08以causal target datagram替换fixed-yield readiness guess，均不改变product behavior | T05 full/targeted convergence、T07/T08 fresh full Architect/QA PASS；quick `5/5`、full `6/6`、milestone budget PASS；exact local/remote scopes consumed/revoked；no release/publication |
| 2026-07-30 | M3 close | M3 改为 `closed`；七票 done、一票诚实 deferred/T06 replacement；接受 exact `d9e59d78...` run `30494736004/1` 的七项同 run 资格，并以 docs-only `d784b061...` 为 closeout source | 全部八项 exit criteria、七项 context inventory、milestone ratchet 和 bounded review histories 均满足；三方 close review 无 blocker/major | Product `PASS_WITH_NOTES`、Architect `PASS_WITH_NOTES`、QA `PASS`；verified context audit、M3 handoff、budget baseline；close 未 push/publish |
| 2026-08-01 | M4 plan | M4改为`planned`；SPEC/TEST-0005固定GitHub-hosted `M4-GHA-01`、diagnostic throughput profile、唯一bounded 10k-idle gate及两票drain DAG；本机WSL2仅作test-code diagnostic | M3已关闭且pre-M4 lifecycle/control repairs已在exact `7019256`集成；复用既有harness、active metric、reference pin与workflow，仅新增一个hosted job，不新增workflow、产品surface、dependency、ADR或optimization ticket | baseline `701925681df78ad83076ed67863bf4fecf46f77c`；M4 milestone、SPEC/TEST-0005、M4-T01/T02；plan-only，无remote/release/publication |
| 2026-08-01 | M4 execute blocker | M4改为`executing`，M4-T01因`M4-BUDGET-001`在candidate commit前blocked；保留isolated working tree，不绕过hook | required driver在ticket-owned `tests/m0-harness`下被pinned rustloc计为1,802行test growth，超过allowance 120；无合法in-scope缩减 | focused local gates PASS；alternate-index machine gate `BLOCKED reason=ticket_allowance_exceeded`；Architect `ESCALATE`；无push/hosted run/publication |
| 2026-08-01 | M4 budget recovery | 批准把non-test driver移入独立non-shipping `tools/ferrum2-m4-qualification` package并恢复T01；CLI/profile、baseline和remote边界不变 | rustloc按路径正确分类；把资格工具放在tests树外符合其职责，不需要修改120行allowance、classifier或独立evidence | 用户采用推荐方案；M4-T01 `ready`；无push/hosted run/publication |
| 2026-08-01 | M4-T01 integration | exact `7730ec7`集成non-shipping Cargo driver和既有workflow的单一`performance` job；T01 `done`、T02 `ready` | 独立tools seam保持产品依赖单向；双审修复fixed throughput window、worker join、absolute drain与sample-slot fail-closed；预算政策不变 | Architect/QA final `PASS`；quick、MSRV、Clippy、self-check、harness及ticket budget `PASS_ADVANCE`；无push/hosted run/publication |
| 2026-08-01 | M4 first hosted qualification | exact `4cee0a1` run `30697247986/1` 的quality、MSRV、interop和三平台全部success，但performance在preflight与release build成功后以`bounded identity probe failed`终止，final qualification failure；T02 `blocked` | 共享`probe_text`丢弃了具体probe及timeout/nonzero/truncation/secret失败类别，不可变日志无法在不猜测的前提下定位；未throughput/resource证据 | `M4-REMOTE-4cee0a1-A1` 1/1在non-force push前消费并自动撤销；cleanup success；失败run保留且不重跑/拼接；无第二push/release/publication |
| 2026-08-01 | M4 probe repair authorization | M4-T02从`blocked`恢复为`active`，临时租用资格驱动的单一`m4_support` source，先修复static redacted probe identity/failure class并在WSL2诊断5秒边界 | 确定缺陷在共享probe seam；不改product/wire/reference/ratio/resource或same-run gate | 用户授权本地修复与WSL2 diagnostic；不授权push/rerun/dispatch/release/publication |
| 2026-08-01 | M4 local probe repair | exact `57d317d`以static probe identity、distinct redacted failure class和shared 30秒probe limit关闭本地诊断缺陷；`IO_TIMEOUT`/`REAP_TIMEOUT`仍为5秒，双审、Full `6/6`、budget通过，T02转为remote-blocked | WSL2 native checkout在旧5秒边界50/50通过；受控6秒`git status`准确命中timeout class，旧hosted具体命令因历史日志折叠不可恢复 | Architect/QA `PASS`；code `13812`、tests `20740`、ratio `1.501593`；等待fresh exact-SHA单次remote授权 |
| 2026-08-01 | M4 second hosted qualification | exact `57d317d` run `30698815475/1`通过quality、MSRV、interop、三平台与throughput，记录ferrum/reference `7977915/478773248`、ratio `0.016663243`；resource在pre-load以`metrics readiness timed out`失败，final failure | driver在创建首个flow前要求active series，但Prometheus labelled family只在首个flow时实例化；WSL2 exact resource `2/2`复现，独立scrape证明HTTP/OpenMetrics有效而series缺失 | `M4-REMOTE-57d317d-A1` 1/1消费撤销；cleanup success；`HOSTED-M4-T02-001` resolved、`HOSTED-M4-T02-002` active；无rerun/第二push/release/publication |
| 2026-08-01 | M4 local resource-readiness repair | exact `56aadd4`只在HTTP 200、唯一终止`# EOF`及稳定eager replay identity/sample完整时把缺失lazy active series解释为zero；其余状态、重复/畸形/未知exposition仍fail closed，post-load exact `10000`不变 | exact `57d317d` WSL resource `2/2`失败及独立scrape定位lazy family circular wait；修复后同path通过25秒readiness观察并cleanup | Architect/QA `PASS`；self-check `mutations=11`；Full `6/6`；code/tests/ratio `13879/20740/1.494344`；等待新的单次exact-SHA remote授权 |
| 2026-08-01 | M4 third hosted qualification | exact `2f4190c` run `30700273019/1`通过quality、MSRV、TCP/UDP `12/12`、三平台及throughput，记录ferrum/reference `9013384/480717482`、ratio `0.018749857`；resource完成readiness、10k与180 samples后以RSS window 2超过105%失败 | validate顺序证明全部active/fd/task tuples稳定；runner-temp raw samples按合同删除，但error未保留binary与first/current medians，无法区分测量扰动、早期baseline、真实增长或runner噪声 | `M4-REMOTE-2f4190c-A1` 1/1消费撤销；cleanup success；`HOSTED-M4-T02-002` resolved、`HOSTED-M4-T02-003` blocked；无rerun/第二push/release/publication |
| 2026-08-01 | M4 RSS diagnostic authorization | M4-T02从`blocked`恢复为`active`，只允许资格driver单文件为RSS threshold failure增加bounded client/server first/current medians及exact self-check | 现有error丢弃已计算数值，无法从已删除raw evidence定位真实根因；105%门限、profile、product和remote边界不变 | `M4-LOCAL-RSS-DIAG-001`消费撤销；允许TDD、双审、Full、budget；不授权push/rerun/dispatch/release/publication |
| 2026-08-01 | M4 local RSS diagnostic repair | exact `7b63bd5`在共享`validate_samples` threshold error中加入window及client/server first/current median-twice KiB，并把既有RSS mutation强化为exact diagnostic assertion；mutation count仍为11 | 同一release self-check先以旧generic error RED、再GREEN；105% u128 comparison、10k、5分钟/180 samples/六窗/2分钟drain及product均不变 | Architect/QA `PASS`无finding；focused checks与ticket/milestone budget `PASS_ADVANCE`，code/tests/ratio `13897/20740/1.492408`；等待Full及新remote授权 |
| 2026-08-01 | M4 fourth hosted qualification | exact `4468f75` run `30704646072/1`通过quality、MSRV、TCP/UDP `12/12`、三平台及throughput，记录ferrum/reference `9035229/547376332`、difference `-98.349357020%`、ratio `0.016506430`；resource完成10k与180 stable samples后server RSS window 2增长`9.4897%`，client不变 | bounded medians排除client及owner-count增长，但当前`VmRSS`信号不足以区分产品leak、延迟驻留、plateau或Linux异步RSS计账；WSL完整pass不替代hosted | `M4-REMOTE-4468f75-A1` 1/1消费撤销；performance/final qualification failure、cleanup success；无rerun/第二push/release/publication |
| 2026-08-02 | M4 paired-RSS diagnostic authorization | M4-T02恢复`active`；保留现有`VmRSS` 105% gate，只在non-shipping driver增加strict `smaps_rollup`解析、all-six paired trajectories及self-check RED→GREEN | 配对信号可区分异步计账、一次性驻留与持续增长，不改变10k、时序、drain、product、workflow或正式profile | `M4-LOCAL-RSS-PAIR-001`授权one writer、双审、Full、budgets及完整native ext4 WSL2 resource diagnostic；无push/rerun/dispatch/PR/release/publication |
| 2026-08-02 | M4 local paired-RSS diagnostic | exact `1d3c117`保留正式`VmRSS` 105% gate并加入64 KiB strict `smaps_rollup` parser、paired samples和all-six bounded trajectories；初版因parser缺少历史RED被QA阻塞，唯一重做以九个public-CLI slices关闭 | native-ext4 WSL 20次1 GiB rollup读取平均/最大`12146/12992` us；完整run `2103.6`秒通过10k、180/180、6/6、drain，六窗VmRSS与precise Rss均为client/server `1908928/1966960` median-twice KiB，THP为0；189行/73224-byte raw JSONL及failed-start目录摘要后删除，未commit/upload | Architect `PASS_WITH_NOTES`、QA `PASS`；Full `6/6`、ticket/milestone budget `PASS_ADVANCE`；scope消费撤销，T02 remote-blocked；无push/rerun/dispatch/PR/release/publication |
| 2026-08-02 | M4 paired-RSS hosted qualification | exact `a53a5d7` run `30710439015/1`通过quality、MSRV、interop、三平台和throughput，记录ferrum/reference `9651268/476676096`、ratio `0.020247015`、difference `-97.975298514%`；resource完成10k与180 stable owner samples后window 2失败 | 六窗`VmRSS`与precise `Rss`逐项相等，增长全为Anonymous；client/server `AnonHugePages`最终达到`2387968/2437120` median-twice KiB并与RSS最终平台同步，排除RSS-accounting-only并反对owner-count growth；hosted allocator/kernel因果仍未证实 | 当时`M4-REMOTE-a53a5d7-A1` 1/1消费撤销；performance/final qualification failure、cleanup success；后续修复与授权见下一行 |
| 2026-08-02 | M4 selected THP profile repair and remote authorization | exact `2305945`以hosted `max_ptes_none=0`、双重driver验证及workflow exact restore/readback完成本地修复；正式10k、180 samples、六窗、105%、owner和drain contract不变 | Reviews、Full `6/6`、ticket/milestone budgets及native-ext4 WSL2 diagnostic通过；WSL2完成10k、180/180、6/6、drain及`0`→`511` restore但仅作diagnostic | local scope消费；`M4-REMOTE-FINAL-A1`授权final closeout SHA一次non-force push及automatic push run，尚未消费；无rerun/dispatch/PR/release/publication/第二push |
| 2026-08-02 | M4 final hosted attempt and quality repair authorization | exact `35fb3f8` run `30725843401/1`通过performance、MSRV、interop和三平台；performance完成`8580846/481626248`、ratio `0.017816400`、THP apply/restore、10k、180/180、6/6及drain，quality在`udp_local_e2e.rs:224`因并行released-port竞争失败 | 产品尚未启动；native-ext4 WSL pre-fix默认并行第4次复现相同`occupy UDP`/`EADDRINUSE`。选择复用现有文件级stdlib Mutex串行五个测试 | `M4-REMOTE-FINAL-A1`消费撤销；`M4-QUALITY-PORT-LOCK-001` active，仅授权本地修复/验证；无push/rerun/dispatch/PR/release/publication |
| 2026-08-02 | M4 local quality harness repair | exact `5f4fed7`在`udp_local_e2e.rs`复用一个文件级stdlib Mutex，五个测试全程持锁；不改product、helper、dependency、workflow或全局test threads | pre-fix native-ext4 WSL第4次RED；修复后default parallel和minimal pair各200/200，ignored IPv6及完整native-ext4 harness通过，Full 6/6、ticket/milestone budgets PASS_ADVANCE | `M4-QUALITY-PORT-LOCK-001` done；local scope消费，无push/rerun/dispatch/PR/release/publication；T02等待新的exact-SHA remote授权 |
| 2026-08-02 | M4 TCP_NODELAY authorization | 新增窄幅`M4-TCP-NODELAY-001`，在共享accepted-stream与post-connect seam默认启用TCP_NODELAY，覆盖client/server数据面TCP | 用户明确要求该优化并授权完成本地验证后推送；不新增配置、依赖、wire或operator surface | `M4-REMOTE-TCP-NODELAY-A1`授权最终validated exact SHA一次non-force push及automatic push run；无rerun/dispatch/PR/release/publication/第二push |
| 2026-08-02 | M4 local TCP_NODELAY optimization | exact `c0de9bd`在共享post-connect与accepted-stream seam设置TCP_NODELAY；不新增配置、依赖或重复binary call sites | Windows两次public-seam RED分别证明outbound/accepted默认false，修复后focused 9/9；native-ext4 WSL focused/runtime及Windows Quick/Full通过 | Full `6/6`；ticket/milestone budget `PASS_ADVANCE`为code/tests/ratio `14173/20878/1.473083`；remote scope尚未消费 |
| 2026-08-02 | M4 TCP_NODELAY final push scope | TCP_NODELAY candidate及首个docs-only descendant均通过Full `6/6`；最终exact tree进入pre-push复核 | 用户本轮明确要求完成后推送；保持一次non-force push与automatic run边界 | `M4-REMOTE-TCP-NODELAY-A1`为本次push消费撤销；run pending；无retry/rerun/dispatch/PR/release/publication/第二push |
| 2026-08-02 | M4 close | exact `9b379a4` run `30730883667/1`通过performance、Full/security/process、MSRV、TCP/UDP `24/24`、三平台、test budget与final qualification；M4 closed | TCP_NODELAY后ferrum/reference medians为`50860305/476470749` B/s、ratio `0.106743814`、difference `-89.325618602%`；THP apply/restore、10k、180/180、6/6、drain、cleanup全部PASS，ratio仍仅诊断 | Formal close review及finding closure记录于`docs/ci-status.md`；单次non-force push scope消费撤销；未rerun/dispatch/PR/package/release/publish；本地closeout不再push |
| 2026-08-02 | M5 plan | M5改为`planned`；接受exact vendored/controlled-patch单实现决策、SPEC/TEST-0006及T01→T02→T03串行DAG | 原包的TCP nonce、zeroization与AES-UDP header API不足以由纯wrapper同时满足安全语义和删除旧实现；最小patch限定于crypto primitive边界并复用既有KAT、interop、MSRV、三平台和performance harness | baseline `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`；M5 research、ADR-0025、SPEC/TEST-0006及三票；plan-only，无产品修改、push、hosted run、release或publication |
| 2026-08-02 | M5 local qualification blocked | T01/T01R/T02完成；local-only exact `816fa7b`通过Full、Rust 1.85、review与milestone budget，T03改为`blocked`、M5为`validating`/close `BLOCKED` | required same-SHA hosted三平台、TCP `12/12`、UDP `12/12`、performance/resource/final summary未获push授权且未运行；`QA-T03-001`禁止local替代或旧run拼接 | Architect local `PASS`；QA local `PASS`/overall `BLOCK`；无remote、ratchet、release或publication；等待新的独立exact-SHA授权 |
| 2026-08-02 | M5 close | exact `6ca0434` run `30743888837/1`通过Full/security/process、MSRV、TCP与UDP各`12/12`、三平台、performance/resource、test budget与final qualification；M5 closed | performance记录ferrum/reference `138726604/484138461` B/s、ratio `0.286543242`、difference `-71.345675840%`；10k、180/180、6/6、drain、cleanup全部PASS，ratio仍仅诊断 | Final Architect/QA均`PASS`，`QA-T03-001`关闭；单次non-force push scope消费撤销；未rerun/dispatch/PR/package/release/publish，本地closeout不再push |
| 2026-08-02 | M6 plan | M6改为`planned`；接受显式opt-in、control-owned per-association sockets、TCP-peer-IP/fixed-or-learned-port authorization和existing-runtime reuse；批准SPEC/TEST-0007及T01→T02→T03 DAG | M5已关闭且SIP022 UDP/runtime完整可复用；最小public path无需routing、shared listener、新trait或新provider，sing-box zero-port hint由advisory-address profile兼容 | baseline `35354f274847d2608a2009e04aaa3b17fb4fa8f4`；M6 research、ADR-0026、SPEC/TEST-0007；plan-only，无产品修改、push、hosted run、release或publication |
| 2026-08-03 | M6 close | 关闭M6；quality、MSRV、三平台和interop四组same-SHA success即为用户授权的hosted完成条件；performance及其dependent aggregate不要求、不计入且不声称PASS | M6不新增performance threshold/claim；public UDP产品、安全、生命周期、budget和interop证据已由本地门禁及四个hosted组覆盖 | exact `7f1e45c174e749d3dddd32d187365722cce94dbe`；run `30765897553/1`；single push consumed |
| 2026-08-03 | M7 plan | M7改为`planned`；接受additive tagged static graph、global unique tags、preflight references、aggregate state/budgets和existing process transaction；明确不建`Endpoint` interface | M6已关闭；config与process deep modules足以承载多个concrete roots，当前没有第二个真实Endpoint adapter或routing requirement | baseline `302fd777f4da62a8c1d4d52d81502056f02089c8`；ADR-0027、SPEC/TEST-0008及四票；plan-only，无产品修改、push、hosted run、release或publication |
| 2026-08-03 | M7 execute start | M7改为`executing`，唯一ready frontier M7-T01改为`active`并绑定独立ticket worktree | `master@96a088e227dcfe415985c3deb081c807fb5e7d90`干净且未移动；M6 closed，M7 contracts approved | exact ticket base `96a088e227dcfe415985c3deb081c807fb5e7d90`；test-budget verify PASS；无push/hosted run/release/publication |
| 2026-08-03 | M7-T01 fail-closed scope repair | T01临时拥有两个binary `run.rs`，multi-inbound run在任何subscriber/runtime/listener副作用前返回既有`startup.protocol`；T02/T03只在完整消费graph时分别移除guard | config loader无法区分`--check-config`与run，原config-only ownership会让已接受的multi-entry graph被单实例binary静默截断 | Engineer pre-edit BLOCKED证据；T01/T02/T03与TEST-0008同步；不新增error、dependency、surface或remote action |
| 2026-08-03 | M7-T01 integration | exact `f6ee43f`集成legacy/tagged完整graph、resolved concrete collections和两个临时fail-closed guards；T01 done，T02 ready | QA full evidence blocker由一次test-only repair关闭；Architect targeted redaction blocker触发用户指定的双独立xhigh分析，两者一致推荐单helper修复，final双审PASS | config `6/6`、CLI `5/5`、Clippy/fmt、Quick、ticket budget `PASS_HOLD` debt `108/120`与diff-check PASS；无push/hosted/release/publication |
| 2026-08-03 | M7-T02 CLI ownership repair | T02改为active；serialized T02/T03共同拥有`config_cli`过渡行，分别移除server/client临时guard并更新该角色的closed startup结果 | T02 focused PASS后Quick只失败于T01刻意保留的server `startup.protocol`断言；产品已正确组合并到达被占端点的`startup.bind`，原T02 ownership无法更新依赖测试 | exact base `44eeedf736c62db185cc032d9e23e2af5bc7c3c3`；首次Quick失败证据保留；不扩展产品范围、dependency或remote action |
| 2026-08-03 | M7-T02 integration | exact `b864a40`集成server tagged TCP/UDP/direct roots、aggregate replay/admission/UDP owners和七位置原子rollback；T02 done，T03 active | 初审发现per-root shutdown可提前清理shared UDP state；一次bounded repair把signal/cancel提升到shared runtime owner，并补齐two-root drain/fatal、byte和owner evidence；双定向复审PASS | candidate `d1b3dbe`；focused、Quick、Full、MSRV、ignored lifecycle、budget `PASS_HOLD` debt `99/120`与integration复验PASS；stale-bin首次CLI失败由required bin build关闭；无push/hosted/release/publication |
| 2026-08-03 | M7-T03 integration | exact `b3f7ff8`集成client tagged SOCKS TCP/UDP roots、static captured outbound和process-wide admission/session/byte/live-ID owners；T03 done，T04 active | 初审发现accept error被折叠及composed UDP、独立byte、live-ID、listener-fatal证据缺口；一次bounded repair全部关闭，定向Architect/QA均PASS | client `27/27`、CLI `5/5`、focused、Full `6/6`、ignored lifecycle、MSRV、Clippy/fmt/diff与integration复验PASS；首次MSRV Windows UDP bind竞态由isolated及unchanged rerun关闭；budget `ratio_ceiling_exceeded`按用户T03/T04 waiver仅记录；无push/hosted/release/publication |
| 2026-08-03 | M7-T04 native ownership repair | T04 ownership增加现有`tests/platform/qualify_native.py`，供唯一bounded repair在既有三平台driver内加入tagged offline与multi-listener rollback/rebind | 初始T04 ownership只列`m0_qualification.rs`，但native jobs直接调用Python driver；不扩权会允许legacy-only平台结果误记为M7 evidence | candidate `564e11e`初审Architect/QA均BLOCK；只扩一个现有文件，不加provider/job/workflow/dependency，remote仍未授权 |
