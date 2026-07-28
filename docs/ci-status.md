# CI 与验证状态

## 当前 M2 execute 状态

- **Wave-3 T04 product integration:** exact
  `980540bd439c438eb196cbc3096cbea0cda3fb4d`; contains initial T04
  candidate `aac21f48b6bd3cb3aa940a60628e5b94eaac89d6`, lifecycle repair
  `6896c6e026797cd62fd9787a66abcca6ec6c7b58`, and mechanical
  integration-evidence repair `c6ade6d34ee95767852cfa25327a4fb6da520a46`.
- **Wave-3 reviews:** full Architect/QA `BLOCK` findings
  `ARCH-M2-T04-001` and `QA-M2-T04-001` were resolved by the one
  substantive repair; both targeted reviews returned `PASS_WITH_NOTES`.
  `M2-T04-INTEGRATION-001` was resolved by isolating legacy TCP-only
  fixtures from default-enabled UDP without weakening config/dual-bind
  evidence. Exact-SHA Architect/QA integration reviews both
  `PASS_WITH_NOTES`; `QA-M2-T02-N01` is satisfied.
- **Wave-3 local gates:** exact binary build, authoritative quick `3/3`,
  full `4/4`, focused/workspace all-features 100-cycle lifecycle,
  workflow validation/review/integration checks, and diff checks all exit
  `0`. Ticket budget `PASS`: code `11582`, tests `18721`, ratio `1.616`,
  baseline `2.041`; delta `954/774`, allowance `1074`.
- **M2-T05 escalation:** initial `6c321ebbed07e426e66b8257792920595cfc0dd2`
  and repaired `975276a90b6ae4b5a9bd984bcc31e3709d473ed5` were not
  integrated. Targeted Architect/QA both `ESCALATE`: the restored TCP
  driver violates ADR-0014 pre-FIN reverse-equality ordering, and the
  mandatory ticket budget fails (`132/523`, allowance `252`; repair
  `0/815`, allowance `120`). `M2-T05-REVIEW-001` remains open; no further
  automatic repair/review is permitted.
- **Wave-2 product integration:** exact
  `6e54cce52e5e29135acd91f6337a4516a094852e`; contains initial M2-T02
  candidate `0d88666d2f46ef85b376c12c55ffb34a784a8451`, repaired candidate
  `4d1c65b4d9af03f008b51cae3b5f058ca1edea64`, and coordination-only
  review-note commit `d268f46435830bdf4f392618071b90ce4b7cee1f`.
- **Wave-2 reviews:** QA full `PASS_WITH_NOTES`; Architect full `BLOCK` on
  `ARCH-M2-T02-001`, followed by the one substantive repair and targeted
  `PASS`. Exact-SHA Architect/QA integration gates both `PASS_WITH_NOTES`.
  The root is resolved; accepted debt `QA-M2-T02-N01` requires T04 to place
  request and response protocol commits inside T03 reserved closures.
- **Wave-2 local gates:** workspace binary build, authoritative quick 3/3,
  authoritative full 4/4, workflow validation/review-state/integration-gate
  checks, and `git diff --check` all exit 0. Ticket budget `PASS`: code
  `10628`, tests `17947`, ratio `1.689`, baseline `2.041`; delta
  `918/1010`, allowance `1038`.
- **Wave-1 product integration:** exact
  `0dff5c104149e7042f5e62dc10831f208a0e16ad` on
  `codex/integration/m2`; contains repaired M2-T01 candidate
  `c7ebe918e2d02664ec21fcfad85c301cbb6d3c01` and repaired M2-T03
  candidate `491954d8ea8fdf5faad17b0b360f353283d44898`.
- **Reviews:** T01 QA full `PASS`; Architect full `BLOCK` on
  `ARCH-M2-T01-001`, followed by one substantive repair and targeted `PASS`.
  T03 Architect/QA full `BLOCK` on `ARCH-M2-T03-001` and
  `QA-M2-T03-001`; one combined repair received both targeted `PASS`
  verdicts. Wave-1 exact-SHA Architect and QA integration gates both `PASS`;
  no blocker/major finding or accepted review debt remains.
- **Local gates:** workspace binary build, authoritative quick 3/3 and full
  4/4, workflow validation/review-state/integration-gate checks, and
  `git diff --check` all exit 0. An initial full run lost an exact lifecycle
  rebind race to the user's existing `sing-box.exe`; the focused harness
  passed 5/5 and the unchanged-candidate full retry passed. This is recorded
  as environmental evidence, not a product waiver.
- **Test budget:** combined ticket gate `PASS`: code `9710`, tests `16937`,
  ratio `1.744`, baseline `2.041`; delta `1990/1178`, allowance `2110`.
- **Remote/release:** nothing pushed or published. IPv6-capable T04
  platform evidence, M2-T05 hosted TCP+UDP qualification, and exact-SHA
  remote evidence have not run and are not credited. T01-T04 are locally
  integrated; T05 is blocked at bounded review convergence before
  integration.

## 当前 M1 closeout 状态

- **Current product/control integration checkpoint:**
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef` on
  `codex/integration/m1`；包含 product checkpoint
  `fba23ca0b628bd6935d0977e3d9df7836b957e78`、reviewed M1-T01 candidate
  `4223051eeae35220b150461cad91daf09a954423` 与 M1-T02 candidate
  `ae84631c515933f60b2aa3f898a86fa3cff11ce9`，以及 M1-T03 candidate
  `4c9ad421e0ef5d193e29e70ed5a674cb30a4aa88`、M1-T04 candidate
  `b7a69899e4053e78fe8824e2cd9215b9d232e106`。本地 workflow-control
  commits `91bb86b`/`3bdde10` 支持并审计一次性 superseding review；
  `81345fbb56ac4cdbf1aea3a3f020d6fd514b187f` 恢复 ticket/milestone
  test-budget gate 的既有分层语义；`02c7bc7` 是其 integration commit，
  `874c83d` 增加 execute close-gate evidence。closeout source
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 只增加 hosted evidence
  文档，不是新的 product/release SHA。
- **Date/environment:** 2026-07-28（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1；Python 3.11.9。
- **Reviews:** T01 Architect full `PASS`、QA full `PASS_WITH_NOTES`
  （advisory `QA-M1-T01-001`）。T02 初始 Architect/QA full `BLOCK`
  （`ARCH-M1-T02-001`/`QA-M1-T02-001`）；first repair 后 QA targeted
  `PASS`、Architect targeted `ESCALATE`；one-use user-authorized additional
  repair `ae84631c` 后 Architect superseding `PASS`。canonical root
  `M1-T02-REVIEW-001` 已关闭，历史记录未覆盖。T03 Architect/QA full 均
  `PASS_WITH_NOTES`，无 blocker/major/repair；notes 为
  `ARCH-M1-T03-001`、`QA-M1-T03-001/002`。T04 Architect/QA full 均
  `PASS`，无 finding/repair。M1 closeout 的 Product Manager、Architect 和 QA
  均 `PASS_WITH_NOTES`；没有新 blocker/major finding。`QA-M1-CLOSE-A01`
  是由本次 roadmap、CI、handoff 和 baseline commit 完成的程序性 close 动作，
  不是 candidate defect。
- **Ticket/quick evidence:** T01～T04 ticket commands 均 exit 0。T03 Team Lead
  admission 的 config/client/server 31 tests 与五个 harness targets 17 tests
  均 PASS；T04 qualification entry 只 build，pure contract 10/10 PASS，未执行
  external entry。最终 integration binary build、fmt、workspace all-target check
  与 workspace tests 均 exit 0。
  clean integration target 首次 quick 的 workspace tests 因 process binaries
  尚未 build 而 exit 101；`cargo build --workspace --bins --locked` exit 0 后，
  同一未修改 SHA quick 3/3 exit 0。该 setup-order derivative 已记录为 review
  debt，不是 product blocker。
- **Full evidence:** close mode 在 final exact integration `874c83d` 重跑
  workspace binary build 与 authoritative full：
  `cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、
  `cargo test --workspace --all-features --locked`、
  `cargo doc --workspace --all-features --no-deps --locked`，4/4 exit 0；
  `git diff --check` exit 0。首次 test wrapper 在 60 秒到达工具执行上限而 exit
  124，没有产生 test verdict；同一未修改 SHA 的捕获式重跑在 92.6 秒 exit 0，
  所以该项是 environment/setup derivative，不是 product failure。
- **Test budget:** T04 ticket gate PASS：code `7386`、tests `15216`、ratio
  `2.060`；delta `+0/+120`，allowance `120`。M1 milestone gate 在
  `874c83d` PASS：code `7720`、tests `15759`、ratio `2.041321`；pre-close
  baseline `7031/14707/2.091737`；required ratchet ratio `2.041737`；
  planning-base delta `+689/+1052` 只报告、不复用 ticket allowance。三方 close
  review 接受 candidate 后，`codex/test-budget-baseline.json` 已以
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 为来源更新为
  `7720/15759/2.041321`。
- **Workflow control evidence:** 66 unit tests、`workflow.py validate`、
  `py_compile`、`git diff --check` 均 exit 0；两项 control hardening findings
  `CTRL-M1-T02-001/002` 在 integration 前关闭。close gate 首次真实 FAIL
  定位为 ticket allowance 被错误复用于 milestone；最小脚本修复及 focused
  pass/fail ratchet regression 已在独立 control worktree 提交并由 Team Lead
  复核，无新授权、豁免或产品改动。closeout docs/baseline working tree 再次
  运行同一 workflow unit suite 66/66 PASS，`workflow.py validate` 与
  post-ratchet `test-budget --gate report` 均 exit 0。
- **Authorization:** three exact single-use local scopes for the T02 additional
  repair, control amendment, and superseding Architect review were consumed and
  revoked。用户随后授权 exact remote qualification；scope
  `m1-20260728-remote-qualification-874c83d-a1` 在 push 前原子消费并因
  `max_uses=1` 自动撤销。没有 force-push、rerun、ref deletion、PR、tag、
  release、publish 或 remote `master` 授权。
- **Scheduler/blockers:** M1-T01～M1-T04 done；当前无 active ticket、release
  dependency 或 open canonical root。pre-close helper action 为
  `ready_to_close`；roadmap durable status 现为 `closed`。close mode 没有
  implementation wave、product repair 或新 authorization。
- **Local qualification notes:** 本 Windows host `[::1]` bind 成功但 raw connect
  返回 `WSAEACCES`，所以 T03 real-process IPv6 row 是 **NOT EXECUTED**；IPv4
  fallback 只证明第三方法 echo/half-close。local platform artifact run 另因
  fixed port 1080 被占而 setup-blocked，不计本机 PASS。同一 exact-SHA hosted
  platform matrix 已补齐 Windows MSVC、Linux GNU、Linux musl success；历史
  IPv6 review note 保留，不把本机 fallback 改写为 IPv6 PASS。close 时对
  authenticated `quality` raw log 的 exact marker audit 证明
  `success_bounded_method_matrix_preserves_bytes_and_half_close` 恰出现一次，
  `SKIP real-process IPv6 row: host IPv6 loopback connect unavailable` 出现零次。
- **Hosted qualification:** exact
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef` 已仅 push 到
  `origin/codex/integration/m1`。GitHub Actions
  [run `30367147537`, attempt 1](https://github.com/zzffu/ferrum2/actions/runs/30367147537)
  为 push event 且整体 **success**；同一 run/attempt/SHA 的 `quality`、`msrv`、
  `platform / windows-msvc`、`platform / linux-gnu`、
  `platform / linux-musl`、`interop` 六项全部 success。interop 的 pinned
  reference provisioning 与 hosted qualification steps success；登录态 raw
  step log 精确包含 `M1-INT-001`～`M1-INT-012` 各一条 `status=PASS`，无
  FAIL/missing/duplicate。没有跨 run 拼接、rerun 或 publication。

## 当前 M0 closeout 状态

- **Current product integration checkpoint:**
  `8318ef106d6cd4e029bd3b02aa64125fabdda462` on
  `codex/integration/m0`; it contains reviewed material for M0-T01～T10.
  Local `master` was fast-forwarded to it, and the current evidence checkpoint
  records all ten durable ticket states as done.
- **Date/environment:** 2026-07-28（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1
- **Latest hosted run:** exact `8318ef106d6cd4e029bd3b02aa64125fabdda462`
  GitHub Actions run `30331336772`, attempt 1, push event，整体
  **success**。同一run/attempt的quality、MSRV、Windows MSVC、Linux GNU、
  Linux musl和interop六项required results全部success；没有跨run拼接。
- **Current implementation frontier:** none；M0-T01～T10均已done。Cargo-managed
  qualification由本机compile/lint与pure-state tests覆盖但不执行external entry；
  hosted profile已收敛为quality、MSRV、三平台matrix及一个四案interop，共四个
  definitions/六个rendered results；11-job self-audit、filter/count、
  linker-help和重复Ubuntu jobs已删除。
- **Current blocker ledger:** M0没有open canonical root。
  `M0-CI-CONVERGENCE`及其`M0-T10-MSRV-FRESH-BINARIES` derivative已由
  exact-SHA local/review gates和run `30331336772`关闭。
- **Authorization:** 一次性scope
  `m0-20260728-final-integration-push-8318ef1`已在正常push前原子消费并耗尽。
  当前没有第二次push、rerun、PR、branch-protection、tag或release授权。
- **Closeout verification:** 2026-07-28 Team Lead在clean
  `codex/integration/m0@8318ef106d6cd4e029bd3b02aa64125fabdda462`
  重新执行authoritative full：`cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、
  `cargo test --workspace --all-features --locked`和
  `cargo doc --workspace --all-features --no-deps --locked`，四条均exit 0。
  GitHub public run page与jobs API只读复核同一SHA/attempt的六项job均为
  `completed/success`；匿名job-log不可见不改变已reviewed fail-closed workflow
  与provider结论的边界。

## 历史修复状态（保留记录）

- **First authorized hosted run:** exact `51fb7327` was pushed only to
  `origin/codex/integration/m0`; GitHub Actions run `30301746374`, attempt 1,
  instantiated all eleven jobs and completed **2 success / 9 failure**. Both
  interop jobs succeeded. The run remains failed historical evidence.
- **Independent hosted-like RED:** Arch WSL current build exit 0；lifecycle
  full-file and full-name exact rerun each exit 101 at the first client-proxy
  exact rebind (`EADDRINUSE`), with no remaining listener and the address in
  `TIME_WAIT`. Independent socket semantics probe exit 0 proved default
  TIME_WAIT rebind fails, old/new Unix reuse succeeds, and a live same-policy
  contender still fails. Broad config `valid` and replay `exact` list commands
  each exited 0 with count 2. WSL MSRV was not run after setup-only `ENOSPC`
  exit 101 and install timeout exit 124；all dedicated temp/process state was
  cleaned.
- **Exact `51fb7327` local gate evidence (Team Lead and independent QA; every
  listed command exit 0):**
  `cargo fmt --all -- --check`；
  `cargo check --workspace --all-targets --locked`；
  `cargo test --workspace --locked`；
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`；
  `cargo test --workspace --all-features --locked`；
  `cargo doc --workspace --all-features --no-deps --locked`；
  `cargo +1.85.0 check --workspace --all-targets --locked`；
  `cargo +1.85.0 test --workspace --locked`；
  `cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked`；
  `cargo test -p ferrum2-m0-harness --test scope_audit --locked`。四个
  `external_interop --ignored --exact <case>` commands各exit 0；local Windows
  release/config/detection evidence也exit 0。最终worktree clean、`target/` absent、
  owned child count 0。
- **M0-T01:** original integration Architect/QA **PASS**；现依用户授权为
  ADR-0009 的一次独占 manifest repair reopen；document Product/Architect
  **PASS_WITH_ACTIONS** 的 required corrections 已完成，QA final **PASS**；
  repair candidate `edaee3d73c5b5e2d7db7bf86a4165565336d8a0a` 已完成
  4-path implementation；Architect/QA ticket gates **PASS**，core 4/4、
  architecture 6/6、workspace-policy 13/13 与全部 ticket commands exit 0；
  lock identities 110→110、0 differences；integration
  `4f3f0ac098fb8f4df054bb52b8ba9f2f93f3cd63` 同组 gates **PASS**，done
- **M0-T05:** `d03e0065efd13ff215cc55be6257c305e8e69175`；
  ticket Architect/QA **PASS**；integrated
- **M0-T06:** `50f547f380d6c58d5538b6540fdc43cb29b5c89c` +
  repair 1/2 `721ed023703601d67dc2cfaad36d31502418373a`；initial
  Architect **BLOCK** / QA **FAIL**，repair re-review 与 final integration
  Architect/QA 均 **PASS**
- **Wave-2 integration:** `999d4f95a2d597fb283689b9306d2a6773af707d`；
  17 个新增路径均属于 T05/T06，final Architect/QA **PASS**
- **M0-T02:** **DONE**；ADR-0004 固定的
  `gcmtestvectors.zip@f9fc479e...a023` 不含批准的 numeric cases。实际来源为
  McGrew/Viega GCM proposal TV archive
  `511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0`
  的 `vec-01.txt`/`vec-02.txt`；ADR-0008 窄勘误已获显式授权，数值向量与
  密码/协议行为不变；contract Architect **PASS**、QA **PASS**。实现
  `45c0e2f` + repair 1/2 `df22d7e` 的 provenance/nonce repair 已 PASS；
  prior overall gate 只因 resolved graph 未启用 `aes/zeroize`/`ghash/zeroize`
  而 BLOCK。ADR-0009/T01 blocker 已由 `edaee3d`/`4f3f0ac` 关闭；combined
  integration `f9e218eca241f3002500b932fdcb4db93c52313b` Architect/QA
  **PASS**，T02 3+2+6、policy 13、architecture 6、core 4 与
  SOCKS5/runtime 36，合计 70 tests PASS；lock identities 110→110、0 differences。
  该历史checkpoint不足以单独证明真实`TcpSealer`/`TcpOpener` private nonce
  owner exhaustion；narrow candidate `6a058035`与integration `bb5c47ec`新增
  exact 2/2 crate-private real-owner tests，全部T02 commands和ticket/integration
  Architect/QA均PASS，worktree clean。T02恢复done；T03 common-SHA mapping仍待执行
- **Current frontier:** 原M0-T03最终integration
  `4bf758ae76421856bb527db3afe165d47e6fd4aa`已通过15项ticket commands、
  T02 exact 2/2、T03 exact 4/4、Architect/QA gates并done。T07 coordination
  checkpoint `ad9e499`之后，Engineer在保留worktree生成clean partial commit
  `52dcdb00a82ed0ab07601f86a985de853c1df00f`：binary build、config CLI 3、
  CLI contract 3、local E2E 4、client endpoint 1、client adapter 5、server
  adapter 6、workspace fmt/check/test与strict Clippy均exit 0；没有manifest/lock/
  lifecycle/native-probe/control-doc change，也未integrate。composition preflight
  发现四个合同证据缺口：黑盒counter visibility、stale fixture native branch、
  fused client connect/first-write、relay error丢partial stats。ADR-0011/0012已
  Accepted，SPEC/TEST amendments已Approved；T03 candidate `8f0d1e0`通过全部15项
  ticket commands（package 64、new filter 1/1），T06 candidate `756a379`通过全部
  ticket commands与package 33；两者scope/lineage/cleanliness检查PASS。T03
  Architect PASS、QA PASS_WITH_ACTIONS（唯一动作是T07后重跑quick）；T06 Architect
  PASS，但QA refined mutation证明read-ahead test在t=0无法排除read activity reset，
  test-only窄repair `0ef7969`以4s delayed read + final 1s original deadline杀死
  mutation。T03/T06分别经`951806d`/`2ce7708`合入local integration；组合
  Architect/QA均PASS，T03 64、T06 33、联合normal/all-features各97 tests及strict
  Clippy/fmt/locked metadata/scope/lineage/cleanliness均PASS，现均done。权威quick
  诊断仅因T07-owned两个`src/main.rs`缺失而未通过，不计PASS。T07保留`52dcdb0`
  并已恢复为`in_progress`。续作发现ADR-0012 required binary paused-time tests因
  两个binary manifests没有Tokio `test-util`且T07不拥有这些路径而无法编译；
  Product/Architect/QA triage均PASS exact two-dev-edge、zero-lock-delta方案；
  勘误base `24ddecf`的三方final document gates均PASS，ADR-0013现为Accepted。
  T07 candidate `5ac8f1b`完成exact dev edges、paused-time/native/lifecycle
  evidence；Architect发现cooperative row假阳性后，repair 1/2 `a9b0a56`用
  bounded target accept与EOF/reset ack关闭。ticket与integration
  Architect/QA均PASS，integrated `91516720`。T08 MSRV preflight暴露T07
  let-chain不兼容；窄repair `50bf0b7`与integration `123618f`通过Rust 1.85、
  focused、quick/full及final Architect/QA，T07 done。T08 checkpoint `14343d2`
  因sing-box evidence边界与静态Architect findings未集成；ADR-0014已在
  `96d6262`接受。repair 1/2 `5accd02`通过Engineer及QA的绝大部分本地执行，
  但final Architect/QA均**BLOCK**：external EOF/shutdown缺少跨线程顺序与
  production-bound mutations、partial I/O可越过absolute deadline、workflow
  policy非closed subset、platform helper存在false-pass/overclaim。repair 2/2
  现于`codex/repair/m0-t08-final-closure`集中关闭。QA首轮MSRV workspace的
  lifecycle flake经独立诊断确定为T07 harness端口ownership TOCTOU：
  `AddrInUse`可由foreign listener造成却被误认child ready；deterministic probe
  1/1复现。T07 first candidate `1974935`经Architect BLOCK后，follow-up
  `6139544`以causal metrics transition、absolute readiness deadline和显式
  failed-child/sibling cleanup关闭全部finding；Architect PASS、QA
  PASS_WITH_ACTIONS。T08 first final candidate `3d5b1a2`关闭workflow/platform
  findings后，follow-up `49c63082`补齐app EOF ack stream hold与fixed operation
  deadline；Architect PASS、QA PASS_WITH_ACTIONS。两者随后已在`51fb7327`
  组合并通过local same-SHA gates；首次hosted失败触发当前ADR-0015/T07/T08
  窄reopen。
- **Contract final verdicts:** 初始review要求exact 47-case matrix、
  `AddressBounds`、harness exact two-edge lock hunk、configured而非hardcoded
  durations、T03/T07 time-evidence ownership和完整ADR模板。全部修正后
  Product/Architect/QA最终均**PASS**，无BLOCKER/REQUIRED/advisory；
  `workflow.py doctor/validate/status/frontier/next`、locked metadata与
  `git diff --check`均exit 0。ADR-0013勘误base `24ddecf`的Product/Architect/QA
  final document gates均PASS；ADR-0013 implementation及T07 quick/full已在
  `91516720`通过。ADR-0014 proposal `f757b58`在causality wording收窄后获
  Product/Architect/QA final **PASS**，acceptance `96d6262`不改变pin/wire/
  product/API；T08 remote evidence仍不提前计PASS。
- **Ticket commits:** `ed2fc9243ceed8e2822319b22182f47936f4c22f`,
  `a13949998535a591f0f0a28542ac2b9bf5a25d15`,
  `cd51226cd1875f80115ac657526e3f9dfb267c14`,
  `4948185c0db282261e045ad1276f5e286f6d7d1d`
- **Commands, all exit 0:** `cargo +1.97.1 metadata --locked --format-version 1`;
  `cargo +1.97.1 test -p ferrum2-core --locked`;
  `cargo +1.97.1 test -p ferrum2-m0-harness --test architecture --locked`;
  `cargo +1.97.1 test -p ferrum2-m0-harness --test workspace_policy --locked`;
  `cargo +1.97.1 tree --workspace --locked`;
  `cargo fmt -p ferrum2-core -- --check`; `git diff --check`;
  focused architecture/workspace-policy CRLF regressions
- **Evidence:** core 4/4、architecture 6/6、workspace policy 7/7；integration
  worktree 最终 clean，无 committed generated artifact、external binary、secret
  或 production endpoint
- **Wave-2 commands, all exit 0:** T05 全部 5 个 ticket commands；T06 全部
  9 个 ticket commands；`cargo test -p ferrum2-socks5 -p ferrum2-runtime
  --locked`（36 passed）；组合 Clippy、fmt、metadata、package trees 和 fixed-base
  `git diff --check`。T06 shutdown regression 在修复后 10,240 次 ready-race
  观察为 0 post-shutdown accepts
- **Historical Wave-2 approved deferrals:** workspace-wide quick/full 等下游 target source 在 T07
  汇合后执行；MSRV、platform、interop 与 GitHub Actions evidence 属于 T08，
  此处不计 PASS
- **Remote at that checkpoint:** origin URL 与只读访问已验证；未 push、未触发
  Actions、未发布

## 规划前历史基线（非当前状态）

- **Branch/commit:** pre-amendment baseline
  `master@5402860136c3233ff1890080099dcddc7d321fee`
- **Date:** 2026-07-27（Asia/Shanghai）
- **Environment:** Microsoft Windows 11 专业版 64-bit，build `10.0.26200`；
  PowerShell `7.6.4`
- **Toolchain:** `stable-x86_64-pc-windows-msvc`；`rustc 1.96.0`；
  `cargo 1.96.0`；`rustfmt 1.9.0-stable`；`clippy 0.1.96`；
  Python `3.11.9`
- **Installed Rust targets:** `x86_64-pc-windows-msvc`,
  `x86_64-pc-windows-gnu`, `wasm32-unknown-unknown`；required Linux
  glibc/musl targets 当前未安装
- **Repository state before bootstrap edits:** clean `master`
- **Result:** 工作流控制面结构有效，但产品验证基线为 **BLOCKED**；没有 Cargo
  workspace、产品测试或 CI，不能描述为 CI green
- **M0 planning state:** ADR-0001～0007 Accepted，SPEC/TEST-0001 Approved，
  M0-T01～T08 ready；ADR-0007 已选择 GitHub Actions/GitHub-hosted runners，
  但 workflow 尚未创建、integration commit 尚未推送，产品与远程 CI gate 仍为
  BLOCKED/NOT_RUN
- **Remote observation:** 本地已有 `origin=https://github.com/zzffu/ferrum2.git`；
  本轮未修改 remote、未验证 push/Actions capability，也未推送。remote
  初始化/URL修正（若需要）与CI branch push仍需用户单独授权

## 规划前历史仓库与自动化清点（非当前状态）

- 无 `Cargo.toml`、`Cargo.lock`、Rust 产品源码、benchmark 或产品 test files；
- 无 `.github` CI workflow 或其他 CI definition；固定路径
  `.github/workflows/m0.yml` 只存在于 ADR/spec/test/ticket 合同；
- bootstrap 时无 non-template contract/ticket；M0 plan与本次amendment现有七份
  Accepted ADR、一份Approved spec、一份Approved test plan、八份ready ticket和
  一份upstream evidence note；
- pre-amendment Git history 为 `88f29f2`（control-plane 初始化）、`b41c612`
  （产品约束/validation commands）、`3024789`（M0 plan）和`5402860`
  （QA agent配置）；
- `workflow.toml` 是 host-local quick/full command 的 authoritative source；
  target matrix、interop、security 和 performance jobs 尚未实现。

## 规划前历史验证记录（非当前状态）

以下命令均在 `C:\project\ferrum2` 运行。退出码是当前 PowerShell/Codex runner
呈现的状态；Cargo 的共同 diagnostic 是找不到根 `Cargo.toml`。

| Date | Branch/commit | Command/job | Exit | Result/evidence |
|---|---|---|---:|---|
| 2026-07-27 | `master@b41c612` | `python3 .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 1 | WindowsApps `python3.exe` alias 未启动解释器且无输出；随后使用已安装的 `python.exe` |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；警告 `No non-template tickets found` |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Workflow validation passed；同一 ticket 警告 |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py bootstrap` | 0 | Bootstrap complete；没有缺失的控制面文件 |
| 2026-07-27 | `master@b41c612` | `cargo fmt --all -- --check` | 1 | 失败：`cargo metadata` 找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` | `cargo check --workspace --all-targets --locked` | 1 | 失败：找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` | `cargo test --workspace --locked` | 1 | 失败：找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；仅有无 non-template ticket 警告 |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 更新后的四份 bootstrap 文档通过 workflow validation |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py status` | 0 | 仅四份预期文档为 dirty；`Milestones: no tickets` |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action: no_tickets`，bootstrap 后应进入 M0 plan |
| 2026-07-27 | `master@b41c612` + M0 plan docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Workflow validation passed；8 tickets、documents、DAG 和 ownership 无 warning |
| 2026-07-27 | same | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0 --json` | 0 | 唯一 selected frontier 为 M0-T01；`skipped=[]`、`warnings=[]` |
| 2026-07-27 | same | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、`ready=8`、selected T01；T02-T08 均只等待显式 blockers |
| 2026-07-27 | same | `git diff --check` | 0 | 无 whitespace error；Git 仅提示既有 Windows LF→CRLF checkout policy |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 六 ADR、一 spec、一 test plan、八 tickets、DAG 和 ownership 全部有效，无 warning |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0 --json` | 0 | 唯一 selected frontier=`M0-T01`；`skipped=[]`、`warnings=[]` |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、8 ready；T02～T08 的等待原因与 ticket blockers 精确一致 |
| 2026-07-27 | same, final M0 plan | `git diff --check` | 0 | 无 whitespace error；Architect 与 QA 最终只读复核均为 PASS、无 BLOCKER/REQUIRED |
| 2026-07-27 | `master@5402860`，amendment preflight | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | `master@5402860`，amendment preflight | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Existing M0 plan workflow validation passed |
| 2026-07-27 | `master@5402860` + M0 CI amendment docs | `git ls-remote https://github.com/actions/checkout.git refs/tags/v6.0.2` | 0 | upstream tag精确解析为`de0fac2e4500dabe0009e67214ff5f5447ce83dd`；只读查询，不访问或修改项目remote |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | ADR-0007、SPEC/TEST、8 tickets、DAG与ownership有效，无warning |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0` | 0 | 唯一selected frontier=`M0-T01` |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、8 ready；T02～T08只等待原有ticket blockers；`warnings=[]` |
| 2026-07-27 | same, M0 CI amendment | `git diff --check` | 0 | 无whitespace error；仅有既有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final M0 CI amendment | Architect final read-only gate | PASS | ADR-0007/0006补充关系、provider/security/evidence、M3边界、ownership与remote授权边界一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, final M0 CI amendment | QA final read-only gate | PASS | AC→test→job→runner→timeout→command→evidence与FAIL/BLOCK一致；无BLOCKER/REQUIRED，仅记录既有LF→CRLF warning |
| 2026-07-27 | `master@b1c4e10` + ADR-0008 docs | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 8 Accepted ADR、Approved SPEC/TEST、8 tickets、DAG与ownership有效，无warning |
| 2026-07-27 | same, ADR-0008 docs | `python .agents/skills/milestone-workflow/scripts/workflow.py status`；`next --milestone M0 --json` | 0 | `done=3, ready=5`；唯一selected frontier=`M0-T02`；`warnings=[]` |
| 2026-07-27 | same, ADR-0008 docs | archive/entry/spec/IPR SHA-256与numeric-case comparison | 0 | `511e…e07f0`、`4fff…137f1`、`6ceb…436a`、`327e…b6c37`、`0170…813d`精确；旧/新/upstream values一致 |
| 2026-07-27 | same, ADR-0008 docs | `git diff --check` | 0 | 无whitespace error；仅有既有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final ADR-0008 contract | Architect final read-only gate | PASS | partial supersession、source classification/hashes/rights、no-binary与no-behavior/scope-change完整；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, final ADR-0008 contract | QA final read-only gate | PASS | M0-CRYPTO-002/T02映射、numeric invariants、frontier与未执行gate状态一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | `master@5a3a89e` + final ADR-0010 contract | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | ADR/SPEC/TEST/T03/T07同步修订、DAG与ownership有效 |
| 2026-07-27 | same, final ADR-0010 contract | `git diff --check` | 0 | 无whitespace error；仅有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final ADR-0010 contract | Product / Architect / QA final gates | PASS | 无剩余BLOCKER/REQUIRED/advisory；wire/product/core/runtime/manifest范围不变 |
| 2026-07-27 | `master@ad9e499` + final ADR-0011/0012 contract | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor`；`validate`；`status`；`frontier --milestone M0 --json`；`next --milestone M0 --json` | 0 | 12 Accepted ADR、Approved SPEC/TEST amendments；T03/T06 selected、T07 blocked、无warning |
| 2026-07-27 | same, final ADR-0011/0012 contract | `cargo metadata --locked --format-version 1`；`git diff --check`；ADR required-section/whitespace/bare-CR audit | 0 | 当前baseline 110 packages；两份ADR模板完整；无whitespace/bare-CR finding，只有既有autocrlf warning |
| 2026-07-27 | same, final ADR-0011/0012 contract | Product / Architect / QA final read-only gates | PASS | configured default/non-default deadlines、evidence ownership、47-case native、exact lock exception、partial accounting与scope一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | `codex/integration/m0@2ce7708` | T03全部16项、T06全部9项、联合normal/all-features package tests、strict Clippy/fmt、locked metadata、scope/lineage/cleanliness | 0 | T03 64、T06 33、联合97/97；Architect/QA组合gate均PASS，无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, pre-T07 diagnostic | configured quick：fmt/check/test | 1/101/101 | 仅缺T07-owned client/server `src/main.rs`；不计quick PASS，须T07汇合后重跑 |

三条 Cargo 失败是当前基线的预期、已记录 blocker，不是测试失败被豁免。full
commands 未运行，因为与 quick commands 具有同一个缺失 workspace 前置条件；
这不是 full gate pass。

## 当前 gate 状态

| Gate | 状态 | 证据/缺口 | 最早解除里程碑 |
|---|---|---|---|
| Workflow doctor/validate | PASS | exact material SHA上的doctor、validate、frontier/next与diff-check均exit 0；无open root | M0 |
| M0 execution contracts | IMPLEMENTED / PASS | 产品/security/platform/reference/exact-SHA结果不变；薄profile与Cargo-managed qualification已集成和review | M0 |
| GitHub Actions workflow | `30331336772` SUCCESS | exact `8318ef1`，attempt 1，整体及六项required results全部success | M0 |
| Local quick/full | PASS | exact `8318ef1` authoritative quick 3/3、full 4/4与workspace binaries build均exit 0 | M0 |
| Security/KAT/negative | PASS | exact `8318ef1`本地full及同SHA hosted `quality` success | M0 |
| Lifecycle/backpressure | PASS | exact `8318ef1`本地full及同SHA hosted `quality` success | M0 |
| External interop | PASS | 同一run/attempt的`interop` success；reviewed fail-closed aggregation要求两个setup成功、qualification exit 0及4/4 | M0 |
| Linux GNU/musl + Windows | PASS | 同一run/attempt三个explicit platform matrix cells全部success | M0 |
| Performance/10k idle | NOT_PRESENT | 无 benchmark contract、runner 或 baseline | M4 |

## 已实现并通过的 M0 CI profile

唯一 workflow 是 `.github/workflows/m0.yml`。trigger 只允许
`pull_request`、push 到 `master`/`codex/integration/**` 和
`workflow_dispatch`，禁止 `pull_request_target`。checkout 固定
`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`、full history；
permissions 只有 `contents: read`，所有 `uses:` 为 full SHA。required jobs
不使用 cache、secrets、cross-job ferrum artifacts或 `continue-on-error`。

| Definition | Runner / cells | Evidence group |
|---|---|---|
| `quality` | `ubuntu-24.04` | workspace binary build + `workflow.toml` full；security/lifecycle/local E2E只运行一次 |
| `msrv` | `ubuntu-24.04` | Rust 1.85.0 all-target check + actual workspace tests |
| `platform` | Windows MSVC、Linux GNU、Linux musl explicit matrix | 两个release artifacts、四次config；GNU/Windows detection；musl static |
| `interop` | `ubuntu-24.04` | Cargo-managed non-test driver固定报告M0-INT-001～004，4/4 |

四个definitions展开六个rendered results；name/count不是永久产品合同。每个job
必须从clean VM/current `GITHUB_SHA`构建并记录runner label、ImageOS、
ImageVersion、OS/kernel、rustc/cargo；platform cells另记录artifact hash/linkage。
GitHub-hosted VM没有OCI image digest，provider-native evidence只用于M0 smoke，
不是M3 qualification。required job启动后失败为FAIL；workflow、
provider、未授权push或job未产生结果为BLOCKED；missing/skipped均非PASS。

M0 close只接受另行授权push后的一个exact integration SHA、一个run ID/attempt中
六个预期rendered results及完整workflow全部success。诊断artifact必须脱敏；
packet capture、benchmark output、
coverage/profiling output 和 rendered docs 属于 generated artifacts，不提交仓库。

## 已知缺口、flakes 与 skipped coverage

- Remote run `30331336772`已在exact `8318ef1`真实执行并整体success，六项结果
  均来自同一attempt。旧`30322690937`与`30301746374`继续保持失败历史，不追认、
  不拼接。
- Windows 上技能文档给出的 `python3` 命令不可用；当前可复现入口是 `python`。
  是否修改 workflow helper 的跨平台调用说明留待单独控制面决策，不阻塞本次文档。
- M0 已固定build compiler 1.97.1、MSRV 1.85.0 check/test、三个target
  triples、reference versions/checksums、fixture provenance、GitHub
  runner/security和unavailable=FAIL/BLOCK contract；job topology不再固定。
  T09/T10实现、exact-SHA local/review gates及同一run/attempt六项success均完成。
- `origin/codex/integration/m0`现精确指向`8318ef1`；一次性push授权已耗尽。
  master remote、PR、tag、release、branch protection、rerun、第二次push及其他
  remote mutation仍未授权。
- 尚未定义 resource stability threshold、soak duration、benchmark hardware
  或 comparison statistics；这是 M4 DEC-010，不阻塞 M0 implementation。
- M0 closeout已重新执行workflow doctor/validate、release dependency checks、
  exact-SHA full gate和`git diff --check`；最终里程碑状态与恢复入口记录在
  `docs/handoffs/HANDOFF-M0-2026-07-28.md`。
