# CI 与验证状态

## 当前 M0 执行状态

- **Current validated local product integration implementation checkpoint:**
  `51fb7327af966cfc3f4a49058ea6bf2284009dcf`
- **Accepted local coordination contract:** this `master` document commit
  contains ADR-0015 plus synchronized SPEC/TEST/T07/T08/roadmap status；its
  exact commit ID is recorded in Team Lead integration evidence rather than
  self-embedded in the commit.
- **Date/environment:** 2026-07-28（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1
- **First authorized hosted run:** exact `51fb7327` was pushed only to
  `origin/codex/integration/m0`; GitHub Actions run `30301746374`, attempt 1,
  instantiated all eleven jobs and completed **2 success / 9 failure**. Both
  interop jobs succeeded. Four jobs share Linux M0-LIFE-005 exact-rebind
  `EADDRINUSE`; two jobs failed their list/count guard because broad filters
  matched two tests; GNU/musl misresolved bare `ld`; Windows hardcoded an
  inapplicable link-help exit. The run is retained as failed evidence and will
  not be rerun, waived, or combined with another SHA/run.
- **Current repair frontier:** ADR-0015 **Accepted**、SPEC/TEST amendments
  **Approved**；final Product、Architect与两个独立QA document gates均**PASS**。
  T07 owns Unix-only listener/rebind plus the exact `socket2` dev edge；T08 owns
  only the two diagnosed full-name `--exact` filters, GNU/musl linker resolution,
  Windows exit/banner evidence and `scope_audit`.
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
| Workflow doctor/validate | PASS | M0 contracts/tickets/DAG/ownership 结构有效，无 workflow warning | 当前 |
| M0 execution contracts | HOSTED REPAIR IN PROGRESS | T07 `6139544`与T08 `49c63082`已在exact `51fb7327`组合并通过local/Architect/QA；hosted run `30301746374`为2/11 success、9/11 failure，ADR-0015/T07/T08已窄reopen | M0-T07/T08 |
| GitHub Actions workflow contract | ATTEMPT 1 FAIL / REPAIR IN PROGRESS | `51fb7327`的唯一authorized run完整实例化11 jobs；两处broad filter和三套linker probes fail closed于错误假设。Job/runner/security矩阵不变，T08只修证据脚本与closed scope policy | M0-T08 |
| Host quick Cargo gate | LOCAL PASS / HOSTED LIFECYCLE FAIL | `51fb7327`上Team Lead与QA独立完成authoritative quick；hosted quick随后只在共同M0-LIFE-005 rebind首因失败 | 当前repair SHA重跑 |
| Host full Cargo gate | LOCAL PASS / HOSTED LIFECYCLE FAIL | `51fb7327`上Team Lead与QA独立完成authoritative full；hosted full随后只在共同M0-LIFE-005 rebind首因失败 | 当前repair SHA重跑 |
| Security/KAT/negative | LOCAL PASS / HOSTED FILTER GUARD FAIL | T02/T03历史与`51fb7327` local evidence保持PASS；hosted security在broad `exact` list/count匹配2 tests时fail closed，目标replay test未执行 | M0-T08 |
| Lifecycle/backpressure | LOCAL PASS / HOSTED FAIL / REPAIR IN PROGRESS | T07 causal readiness/cleanup保持；hosted Linux真实连接后的首个exact rebind在四个jobs一致`EADDRINUSE`。ADR-0015要求Unix-only production reuse、default Windows、same-policy bind+listen及live-owner exclusion | M0-T07 |
| External interop | HOSTED ATTEMPT 1 SUCCESS / M0 CLOSE BLOCKED | T08 `49c63082`四项local exact cases及`51fb7327` run `30301746374`的两个interop jobs成功；ADR-0007禁止把这两个success与新SHA/run拼接，最终新run仍须11/11 | M0 subset，M1/M2 full |
| Linux glibc/musl + Windows | HOSTED PROVIDER PROBES FAIL BEFORE ARTIFACT GATES | GNU/musl把compiler返回的bare `ld`误当checkout相对路径并exit127；Windows `link /?`正确输出usage但exit1，与硬编码1100冲突。T08将fail-closed解析canonical executable/version/banner；artifact/product语义未被本次失败执行到 | M0 smoke，M3 qualification |
| Performance/10k idle | NOT_PRESENT | 无 benchmark contract、runner 或 baseline | M4 |

## 已实现且正在修复的 M0 CI

唯一 workflow 是 `.github/workflows/m0.yml`。trigger 只允许
`pull_request`、push 到 `master`/`codex/integration/**` 和
`workflow_dispatch`，禁止 `pull_request_target`。checkout 固定
`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`、full history；
permissions 只有 `contents: read`，所有 `uses:` 为 full SHA。required jobs
不使用 cache、secrets、cross-job ferrum artifacts或 `continue-on-error`。

| Required job | Runner | Timeout | Evidence group |
|---|---|---:|---|
| `m0-host-quick` | `ubuntu-24.04` | 60 | `workflow.toml` quick |
| `m0-security` | `ubuntu-24.04` | 60 | workspace/security/KAT/replay/binding/redaction |
| `m0-lifecycle` | `ubuntu-24.04` | 60 | abortive-close/lifecycle/backpressure/metrics endpoint |
| `m0-local-e2e` | `ubuntu-24.04` | 60 | config/CLI/SOCKS/endpoint/local process E2E |
| `m0-integration-full` | `ubuntu-24.04` | 60 | full/scope/M0-CI-001～006 |
| `m0-msrv` | `ubuntu-24.04` | 60 | Rust 1.85.0 check/test |
| `m0-windows-msvc` | `windows-2022` | 60 | MSVC artifacts/config + M0-DETECT-002 |
| `m0-linux-gnu` | `ubuntu-24.04` | 60 | GNU artifacts/native config + M0-DETECT-002 |
| `m0-linux-musl` | `ubuntu-24.04` | 60 | musl-tools 1.2.4-2 artifacts/config/static proof |
| `m0-interop-sing-box` | `ubuntu-24.04` | 60 | M0-INT-001/003 |
| `m0-interop-shadowsocks-rust` | `ubuntu-24.04` | 60 | M0-INT-002/004 |

每个 job 必须从 clean VM/current `GITHUB_SHA` 构建并记录 ImageOS、ImageVersion、
Included Software URL、OS/kernel、rustc/cargo/linker；platform jobs另记录artifact
hash/linkage。GitHub-hosted VM没有OCI image digest，provider-native evidence只用于
M0 smoke，不是M3 qualification。required job启动后失败为FAIL；workflow、
provider、未授权push或job未产生结果为BLOCKED；missing/skipped均非PASS。

M0 close只接受另行授权push后的一个exact integration SHA、一个run ID/attempt中
11 job全部success。诊断artifact必须脱敏；packet capture、benchmark output、
coverage/profiling output 和 rendered docs 属于 generated artifacts，不提交仓库。

## 已知缺口、flakes 与 skipped coverage

- Remote run `30301746374` 已真实执行且失败；它不是flake或skipped-pass，也不因
  两个interop success而部分关闭M0。新的exact SHA必须重新产生一个11/11 run。
- Windows 上技能文档给出的 `python3` 命令不可用；当前可复现入口是 `python`。
  是否修改 workflow helper 的跨平台调用说明留待单独控制面决策，不阻塞本次文档。
- M0 已固定 build compiler 1.97.1、MSRV 1.85.0、三个 target triples、reference
  versions/checksums、fixture provenance、GitHub job/runner/timeout/security和
  unavailable=FAIL/BLOCK contract；T01～T08 product slices、workflow与首次runner
  run均已存在。当前缺少的是ADR-0015/T07/T08修复后的新exact SHA artifact/platform
  evidence，以及同一新run/attempt的11/11 success close evidence。
- `origin` exact URL与push capability已验证；仅exact `51fb7327`被推送到
  `origin/codex/integration/m0`并触发run `30301746374`。修复后的新exact SHA仍须
  先通过local integration、Architect与QA并获得separately authorized push，才可
  非force更新同一授权分支并等待新run；master/PR/tag/release/branch protection/
  rerun及其他remote mutation仍未授权。
- 尚未定义 resource stability threshold、soak duration、benchmark hardware
  或 comparison statistics；这是 M4 DEC-010，不阻塞 M0 implementation。
- M0 CI amendment 最终写入后，workflow doctor/validate、
  `frontier --milestone M0 --json`、`next --milestone M0 --json` 和
  `git diff --check` 均须重新通过；最终结果记录在上方验证表。
