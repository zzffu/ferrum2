+++
id = "M0-T09"
title = "Isolate external interoperability behind one hosted qualification seam"
milestone = "M0"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "tests/m0-harness/Cargo.toml",
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/src/bin/m0_qualification.rs",
  "tests/m0-harness/src/qualification/**",
  "tests/m0-harness/tests/external_interop.rs",
  "tests/m0-harness/tests/qualification_contract.rs",
  "tests/m0-harness/tests/workspace_policy.rs",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "cargo metadata exposes one Cargo-managed m0-qualification binary with test=false; workflow.toml quick/full and all-features/all-targets compile and lint it under workspace unsafe, dependency, license, and lock policy but never execute its entry, any external case, download, socket, or external child",
  "The qualification binary is invoked only by the hosted workflow for real interoperability; after a fixed-argument git checkout-identity probe it validates GitHub Actions Linux context, clean checkout, and HEAD equals GITHUB_SHA before any network or socket I/O or reference/ferrum child and accepts no arbitrary URL, binary path, version, checksum, or unreviewed reference",
  "The qualification entry verifies the existing sing-box 1.13.14 and shadowsocks-rust 1.24.0 asset size, SHA-256, safe extraction members, exact version output, and license boundary before execution",
  "M0-INT-001 through M0-INT-004 each retain independent temp, ports, children, absolute deadline, bounded redacted capture, exact two-way 16386-byte comparison, ordered clean EOF, and cleanup; every runnable case is attempted after an independent case fails, all four rows are reported, and exit zero requires 4/4",
  "A deterministic focused test injects failure while provisioning one reference and proves that its two cases report FAIL under one setup root without claiming execution, both cases for the other reference still run, and the four-row summary exits nonzero",
  "The summary schema stays minimal and fixed: case_id, PASS or FAIL, and an optional canonical_root; no repository parser is added for it",
  "Timeout behavior is defined by an absolute deadline and accepts platform-equivalent timeout error kinds without allowing partial progress to slide the deadline",
  "Every removed external helper test is mapped to a retained result, a small hermetic Cargo test, hosted evidence, or an explicitly discarded mechanical assertion; payload, EOF, deadline, bounded capture, failure continuation, and cleanup claims are not silently lost",
  "Local qualification contract tests are pure state tests only: they create no socket or process, read no reference, and access no network; workspace fmt, Clippy with warnings denied, normal tests, all-features tests, and MSRV check/test all cover the Cargo-managed code without running interoperability",
  "No production crate, wire behavior, product API, config, reference pin, target triple, or release graph is changed; any manifest rearrangement uses only existing locked packages and receives focused resolved-graph review",
]
+++

# M0-T09: Isolate external interoperability behind one hosted qualification seam

## Outcome

把true external execution从本机libtest discovery移到一个显式
Cargo-managed non-test deep interface；GitHub一次调用获得四项可区分结果，本机
只编译、lint并运行无I/O的pure state tests，不运行reference interoperability。

## Context

当前四个 ignored cases 引入的 module 仍有 15 个默认 helper tests，因此普通
workspace test 会执行 external evidence machinery。run `30322690937` 的 Linux
timeout-kind失败是该 seam 泄漏的直接表现，不是 interop 产品失败。

## In scope

- 将external qualification改为manifest显式`test = false`的
  `m0-qualification` binary。
- 保留并收拢现有 pin、process、deadline、payload、EOF、diagnostic和cleanup实现。
- 删除 libtest ignored/filter/count interface及默认 external helper self-tests。
- 为四案 aggregation、continue-after-case-failure 和 pre-I/O hosted guard提供
  deterministic focused tests；不得在这些测试中启动 reference binary。
- 记录旧helper claim到pure Cargo test、hosted evidence或discarded mechanic的
  迁移表；不把OS error spelling或rebind
  duplication伪装成保留结果。
- 更新manifest和focused workspace policy，使所有workspace target selection都
  编译/lint qualification但不执行其entry或external cases。

## Out of scope

- 修改 ferrum2 product crates、wire、runtime或config。
- 更换 reference版本、URL、checksum、license结论或四案语义。
- 在本机下载/运行 sing-box 或 shadowsocks-rust。
- 修改 workflow、platform jobs、remote、push、rerun、PR或release。

## Implementation notes and constraints

- branch/worktree必须从Team Lead指定的exact accepted ADR-0017 planning commit
  创建；不得从当前stale `master`丢失`5969bfd`的M0 implementation。
- interface不接受任意operation、URL、binary path或shell command；一次运行固定
  尝试全部四案，pin只来自 reviewed `tests/interop/versions.toml`。
- qualification binary优先使用Rust standard library；若确需dependency，必须先
  扩大票据/合同并完成locked source/version/license与production-graph review。
  调用runner工具时使用closed executable与参数，不拼接shell input。
- 除固定参数checkout identity `git` probe外，非GitHub/exact-SHA环境必须在任何
  network/socket I/O或reference/ferrum child前fail closed。
- 每案 failure转换为sanitized structured result；driver继续尝试其余独立案并在
  最后聚合。
- reference provision failure只记录一个canonical setup root；其两案报告FAIL但不
  声称执行，另一个reference仍运行。全局build/exact-SHA failure可作为共同前置
  root终止case plan，但不得产生部分PASS。
- child/temp/socket均有owner、absolute deadline和bounded cleanup path。
- external case不再重复M0-LIFE-005 exact-rebind proof；同一SHA的quality gate拥有
  restart/live-owner结果。
- 不新增 task runner、container、cache、external binary或 committed result。

## Validation commands

```bash
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo check --workspace --all-targets --locked
cargo metadata --no-deps --format-version 1 --locked
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo tree --workspace --locked
git diff --check
```

qualification的真实interop operation不得在本机执行。Engineer只以pure
deterministic Cargo tests证明guard、aggregation、failure continuation与summary；
实际socket/process/deadline/cleanup四案只进入后续另行授权的GitHub run。

## Risks

- 单 job内四案可能互相污染；必须独立 temp/ports/children并总是cleanup。
- manifest若遗漏`test = false`或任何local test启动entry/external I/O，会重新
  违反local boundary。
- 删除 helper self-tests后，mechanical regression主要由真实四案发现；保留的
  focused tests只覆盖driver自身的聚合、deadline和资源所有权。

## Blocker record

当前 canonical root 是 M0 CI evidence seam错误。旧 run
`30322690937`保持失败；本票完成不授权或替代 hosted qualification。

Final integration QA在exact candidate
`e41dbd23b0f939666094ce0aa3f12c2fbbb127f4`发现
`M0-T09-PROVIDER-STATUS-AGGREGATION`：workflow已持久化provider setup
退出状态，但qualification plan尚未消费它们，因此一次失败setup留下有效文件时
可能错误执行对应cases并报告PASS。修复提交
`cb193a19ec821786684f03839221a528ed1d21dc`现在只消费两个固定status变量，
仅精确`"0"`允许对应reference进入provision/cases；其他值在pure state plan中
fail closed，使该reference的两行共享一个`provision-<reference>` root，同时
继续另一个reference。聚焦测试8/8及exact-SHA Architect/QA复审均PASS，该局部
canonical root已关闭。

## Completion evidence

- Branch: `codex/ticket/m0-t09`
- Commit(s): `f6f160c5cf2204cb009b42292627544534d16917`,
  `cb193a19ec821786684f03839221a528ed1d21dc`
- Required reviewer role/profile and verdict: Architect (`gpt-5.6-sol/max`)
  PASS；QA (`gpt-5.6-sol/high`) PASS；provider-status修复的exact-SHA
  Architect与QA复审也均PASS。实际 launch metadata 不可观察，因此配置未作
  运行时声称，且未使用fast-mode override。
- Exact candidate SHA: `cb193a19ec821786684f03839221a528ed1d21dc`
- Integrated commits: `42f9a96dd90e1d07a89ec485c5e17422431c81b4`,
  `37aba8aa0bf00968507404973ead32d7246f013e` on
  `codex/integration/m0`
- Validation: repair candidate的qualification pure-state 8/8、metadata、
  workspace check、strict Clippy、fmt、tree、Rust 1.85 check、workspace
  binaries build和safe workspace tests均exit 0；集成后的qualification
  pure-state 8/8与workspace policy 17/17也均exit 0。未运行
  `m0-qualification`、reference interoperability、网络、WSL2或任何remote
  action。
