# CI 与验证状态

## 当前基线

- **Branch/commit:** `master@b41c6127b1834ebd97246451fd92bafea50cb205`
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
- **M0 planning state:** ADR-0001～0006 Accepted，SPEC/TEST-0001 Approved，
  M0-T01～T08 ready；这只使 implementation frontier 可执行，不改变产品 gate 的
  blocked 状态

## 仓库与自动化清点

- 无 `Cargo.toml`、`Cargo.lock`、Rust 产品源码、benchmark 或产品 test files；
- 无 `.github` CI workflow 或其他 CI definition；
- bootstrap 时无 non-template contract/ticket；M0 plan 当前已新增六份 ADR、一份
  spec、一份 test plan、八份 ticket和一份upstream evidence note；
- Git history 只有 `88f29f2`（control-plane 初始化）和 `b41c612`
  （产品约束/validation commands）；
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

三条 Cargo 失败是当前基线的预期、已记录 blocker，不是测试失败被豁免。full
commands 未运行，因为与 quick commands 具有同一个缺失 workspace 前置条件；
这不是 full gate pass。

## 当前 gate 状态

| Gate | 状态 | 证据/缺口 | 最早解除里程碑 |
|---|---|---|---|
| Workflow doctor/validate | PASS | M0 contracts/tickets/DAG/ownership 结构有效，无 workflow warning | 当前 |
| M0 pre-implementation plan | PASS | Accepted ADR-0001～0006、Approved SPEC/TEST-0001、ready T01～T08；Architect=PASS、QA=PASS；frontier=T01 | 当前 |
| Host quick Cargo gate | BLOCKED | 无 root manifest/workspace | M0 |
| Host full Cargo gate | NOT_RUN/BLOCKED | quick prerequisite 不成立 | M0 |
| Security/KAT/negative | PLANNED/NOT_RUN | TEST-0001 已映射 required tests；无实现、fixture 或执行证据 | M0 |
| Lifecycle/backpressure | PLANNED/NOT_RUN | TEST-0001 已冻结 deterministic seams；无 runtime 或执行证据 | M0 |
| External interop | PLANNED/NOT_RUN | reference pins/checksums与四项 M0 matrix 已冻结；无 harness/runner evidence | M0 subset，M1/M2 full |
| Linux glibc/musl + Windows | PLANNED/NOT_RUN | 三个 exact targets与 matching-runner smoke已冻结；尚无 artifact evidence | M0 smoke，M3 qualification |
| Performance/10k idle | NOT_PRESENT | 无 benchmark contract、runner 或 baseline | M4 |

## 必需但尚未建立的 CI 层级

后续 test plans 必须为每项 acceptance criterion 指定 test ID、命令、预期结果、
CI job 和 fixture 来源。拟议层级为：

- 每次变更：`workflow.toml` quick gate，并在 integration 运行 full gate；
- security negative jobs：KAT、tamper/truncation、illegal length/address、
  timestamp/replay、request/response binding 和 secret redaction；
- deterministic lifecycle jobs：bounded queue/buffer、backpressure、
  timeout/cancellation、half-close、listener failure 和 graceful shutdown；
- Windows、Linux x86_64 glibc、Linux x86_64 musl target matrix；精确
  triples 和 native/cross 策略由对应 plan 决定；
- 固定 sing-box/shadowsocks-rust version/checksum 的 required interop jobs；
- scheduled soak/repetition jobs；M4 使用固定 runner 执行 performance gate。

required job 缺失或 skipped 不得算通过。诊断 artifact 必须脱敏；packet capture、
benchmark output、coverage/profiling output 和 rendered docs 属于 generated
artifacts，不提交仓库。

## 已知缺口、flakes 与 skipped coverage

- 当前没有 CI，因此也没有可声称的 flakes；所有产品 coverage 都是
  **not present**，不是 skipped-pass。
- Windows 上技能文档给出的 `python3` 命令不可用；当前可复现入口是 `python`。
  是否修改 workflow helper 的跨平台调用说明留待单独控制面决策，不阻塞本次文档。
- M0 已固定 build compiler 1.97.1、MSRV 1.85.0、三个 target triples、reference
  versions/checksums、fixture provenance与 unavailable=FAIL/BLOCK contract；这些
  仍缺实际 workspace、runner 和执行证据。
- 最终门禁期间出现非本次 scope 的 `.codex/agents/qa.toml` working-tree 修改
  （`model_reasoning_effort = "medium"` → `"high"`）。M0 文档提交不得包含或丢弃
  该并发改动；`workflow.require_clean_base=true` 意味着其所有者确认处理前，
  execute preflight 会停止。
- 尚未定义 resource stability threshold、soak duration、benchmark hardware
  或 comparison statistics；这是 M4 DEC-010，不阻塞 M0 implementation。
- bootstrap 文档与 M0 plan 最终写入后，workflow doctor/validate、
  `frontier --milestone M0 --json`、`next --milestone M0 --json` 和
  `git diff --check` 均须重新通过；最终结果记录在上方验证表。
