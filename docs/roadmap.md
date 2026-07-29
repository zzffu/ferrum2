# ferrum2 v0 路线图

## 状态词汇与当前状态

里程碑状态为 `proposed` → `planned` → `executing` → `validating` → `closed`。
状态必须由 contract、ticket、commit 和验证证据支持。

Bootstrap 基线是
`master@b41c6127b1834ebd97246451fd92bafea50cb205`。M0 已以 exact integration
`8318ef106d6cd4e029bd3b02aa64125fabdda462`、本地 full gate 与 GitHub Actions
run `30331336772` attempt 1 的六项成功证据关闭；M1 已以 exact
`874c83d0ee71054bd702d6ecac55e88d9e2fbcef`、本地 full gate 与 GitHub Actions
run `30367147537` attempt 1 的六项成功证据关闭；M2 正在 `executing`，M3-M4
仍为 `proposed`。
durable handoff 位于 `docs/handoffs/HANDOFF-M0-2026-07-28.md` 和
`docs/handoffs/HANDOFF-M1-2026-07-28.md`。

## 依赖顺序

| 里程碑 | 依赖 | 可独立验收的主结果 |
|---|---|---|
| M0 | bootstrap 文档完成 | AES-128-GCM TCP 端到端安全纵切 |
| M1 | M0 closed | 三种方法的完整 TCP 与 12 项 TCP 互操作矩阵 |
| M2 | M1 closed | 三种方法的 UDP 协议 path 与 12 项 UDP 互操作矩阵 |
| M3 | M1、M2 closed | 运维契约、生命周期和三目标平台资格 |
| M4 | M3 closed | 性能/资源门及同一 commit 上的 v0 资格证明 |

M1 已冻结并验证 shared crypto/wire/runtime boundary；M2 Wave 1 已集成
method-bound UDP crypto 与 bounded direct UDP runtime，下一 dependency-ready
动作是 M2-T02 protocol/replay。每个里程碑内的并行 ticket 仍须满足
dependency-ready 和 non-overlapping ownership。

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

- **Status:** ready to close (execute complete; close mode not yet invoked)
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
- **In-scope tickets:** M2-T01、M2-T02、M2-T03、M2-T04、M2-T05 均已
  `done` 并完成本地integration。M2-T05 hosted/platform release
  qualification首轮在superseded SHA `a168b89`失败；随后保留该失败历史，
  修复并在final exact SHA `52d1610a127349e7a817a67c81c77e0383d20d1e`
  的同一push-triggered run/attempt完成通过。
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
  TCP-only fixture isolation关闭；`QA-M2-T02-N01`已满足。IPv6仍
  **NOT EXECUTED**，未 push/publish。

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

  Final local assembly
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

- **Deferred/out of scope:** public client UDP inbound、SOCKS5 UDP ASSOCIATE、
  SIP023/multi-user、routing/DNS proxy/custom resolver、M3 platform/lifecycle
  qualification和M4 performance。
- **Integrated commit:** reviewed and remotely qualified product/control
  commit `52d1610a127349e7a817a67c81c77e0383d20d1e`; coordination-only
  evidence closeout follows locally on the same integration branch.
- **Open blockers and risks:** 当前没有open canonical root；
  `M2-T05-QUALIFICATION-001`已由run `30415717152`的同SHA/attempt证据解决，
  release gate clear，scheduler为`ready_to_close`。`M2-INT-QA-001`仍是
  parallel server-test port/readiness contention的nonblocking advisory；
  `ARCH-M2-T05-HOSTED-N02`的100 ms scheduler bound也保持advisory。只有
  authoritative gate复现或证据指向shipped defect时才建立新root。M2尚未执行
  close mode；唯一新增remote state是上述integration ref的授权fast-forward
  push，没有release/publication。

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
| DEC-008 | resolved in M2 plan | bounded UDP protocol API；8,129-value window；client current+old；session 4,096、16 MiB allocated bytes、depth-4 queues、65,507 wire、300s idle；expired-oldest-or-reject eviction | `ADR-0020`～`ADR-0022`、SPEC/TEST-0003 |
| DEC-009 | partially bounded；M3 plan | M0 已固定 triples/build/config smoke；full native lifecycle/packaging qualification 留 M3 | `ADR-0006` |
| DEC-010 | open；M4 plan | benchmark hardware/config/statistics 与 10k-idle stability threshold | M0 不设性能声明 |
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
| benchmark 不等价或噪声驱动错误优化 | P1 | M4 | frozen comparable config 和重复统计 |

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
