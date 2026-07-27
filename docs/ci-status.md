# CI 与验证状态

## 当前 M0 执行状态

- **Current validated local integration checkpoint:**
  `c2ea5c2b48adf986e17a11639e24184c65131d3b` on local `master` and
  `codex/integration/m0`
- **Date/environment:** 2026-07-27（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1
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
  mutation，全部T06 ticket/package/Clippy/fmt gates PASS并回到`review`。T07 blocked
  且保留`52dcdb0`，T08等待T07。
- **Contract final verdicts:** 初始review要求exact 47-case matrix、
  `AddressBounds`、harness exact two-edge lock hunk、configured而非hardcoded
  durations、T03/T07 time-evidence ownership和完整ADR模板。全部修正后
  Product/Architect/QA最终均**PASS**，无BLOCKER/REQUIRED/advisory；
  `workflow.py doctor/validate/status/frontier/next`、locked metadata与
  `git diff --check`均exit 0。implementation、quick/full、native和remote evidence
  尚未运行且不计PASS。
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
- **Approved deferrals:** workspace-wide quick/full 等下游 target source 在 T07
  汇合后执行；MSRV、platform、interop 与 GitHub Actions evidence 属于 T08，
  此处不计 PASS
- **Remote:** origin URL 与只读访问已验证；未 push、未触发 Actions、未发布

## 规划前基线

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

## 仓库与自动化清点

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

## 本次实际验证

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

三条 Cargo 失败是当前基线的预期、已记录 blocker，不是测试失败被豁免。full
commands 未运行，因为与 quick commands 具有同一个缺失 workspace 前置条件；
这不是 full gate pass。

## 当前 gate 状态

| Gate | 状态 | 证据/缺口 | 最早解除里程碑 |
|---|---|---|---|
| Workflow doctor/validate | PASS | M0 contracts/tickets/DAG/ownership 结构有效，无 workflow warning | 当前 |
| M0 execution contracts | IN_PROGRESS | Accepted ADR-0001～0012、Approved SPEC/TEST amendments且final Product/Architect/QA PASS；T01/T02/T04/T05 done，T03 `8f0d1e0` review passed with downstream quick action；T06 `756a379`+`0ef7969` in review；T07 partial `52dcdb0` blocked，T08等待T07 | M0-T06 re-review |
| GitHub Actions workflow contract | PLANNED/NOT_RUN | ADR-0007 固定 `.github/workflows/m0.yml`、11 jobs、runner/timeout、triggers、permissions、full-SHA actions、no-cache 与 exact-pushed-SHA evidence；YAML 尚未创建 | M0-T08 |
| Host quick Cargo gate | DEFERRED/NOT_RUN | T07 partial branch quick-equivalent fmt/check/workspace test已PASS但未integrate；exact integration quick仍在T03/T06 repairs与T07汇合后执行，当前不计PASS | M0-T07 |
| Host full Cargo gate | DEFERRED/NOT_RUN | quick与完整downstream targets先在T07汇合；当前不计PASS | M0-T07/T08 |
| Security/KAT/negative | T02/T03 historical PASS；native probe PENDING | T02真实AEAD owner 2/2、T03 private 4/4和全部T03 gates已在`4bf758a`PASS；ADR-0011 primitive-only 47-case native probe与policy delta尚未实现 | M0-T07 |
| Lifecycle/backpressure | IN_PROGRESS | T06历史focused gates与10,240次shutdown race PASS；ADR-0012 partial-failure stats repair及ADR-0011 T06/binary-private/100-process compositional evidence尚未完成 | M0-T06/T07 |
| External interop | PLANNED/NOT_RUN | reference pins/checksums、四项 M0 matrix与两个`ubuntu-24.04` clean-VM jobs已冻结；无 harness/runner evidence | M0 subset，M1/M2 full |
| Linux glibc/musl + Windows | PLANNED/NOT_RUN | `windows-2022`/`ubuntu-24.04`、GNU native probe、musl 1.2.4-2/static assertions与provider-native evidence已冻结；尚无 artifact evidence | M0 smoke，M3 qualification |
| Performance/10k idle | NOT_PRESENT | 无 benchmark contract、runner 或 baseline | M4 |

## 已冻结但尚未实现的 M0 CI

唯一 workflow 将是 `.github/workflows/m0.yml`；本次 plan 不创建。trigger 只允许
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

- 当前没有 remote CI，因此也没有可声称的 remote flakes；T01～T06 有历史local
  ticket evidence，T07有未integrate partial evidence，但完整产品/平台/interop coverage 尚未在最终
  integration commit 产生，不是 skipped-pass。
- Windows 上技能文档给出的 `python3` 命令不可用；当前可复现入口是 `python`。
  是否修改 workflow helper 的跨平台调用说明留待单独控制面决策，不阻塞本次文档。
- M0 已固定 build compiler 1.97.1、MSRV 1.85.0、三个 target triples、reference
  versions/checksums、fixture provenance、GitHub job/runner/timeout/security和
  unavailable=FAIL/BLOCK contract；workspace/T01/T05/T06 已存在，这些仍缺其余
  product slices、workflow、runner run 和 artifact evidence。
- 本地 `origin` URL 与只读访问已验证，push capability 与 repository Actions
  settings 尚未验证；当前未修改 remote。用户已条件授权仅在 T08 local
  integration、Architect 与 QA 均 PASS 后 push exact
  `codex/integration/m0` commit 并等待 Actions；其他 remote mutation 仍未授权。
- 尚未定义 resource stability threshold、soak duration、benchmark hardware
  或 comparison statistics；这是 M4 DEC-010，不阻塞 M0 implementation。
- M0 CI amendment 最终写入后，workflow doctor/validate、
  `frontier --milestone M0 --json`、`next --milestone M0 --json` 和
  `git diff --check` 均须重新通过；最终结果记录在上方验证表。
