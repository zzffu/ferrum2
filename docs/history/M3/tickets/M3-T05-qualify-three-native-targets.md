+++
id = "M3-T05"
title = "Qualify native release artifacts on the three required targets"
milestone = "M3"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M3-T06"]
review_blocked_by = []
integration_blocked_by = ["M3-T06"]
release_blocked_by = ["M3-T01", "M3-T02", "M3-T03", "M3-T06"]
required_reviews = ["architect", "qa"]
owns = [
  ".github/workflows/**",
  "tests/platform/**",
]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "One exact candidate SHA produces locked release ferrum2-client and ferrum2-server artifacts for x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, and x86_64-unknown-linux-musl and records the exact SHA, Rust toolchain, runner identity, target, size, and SHA-256 for each binary",
  "Each artifact executes natively on its target runner and both binaries pass help, version, valid and redacted invalid offline config, occupied startup rollback, signal graceful and forced shutdown, and immediate restart or rebind observations using synthetic configuration and bounded timeouts",
  "Windows records PE headers and dependents, Linux GNU records file, ELF headers, program and dynamic sections and GLIBC requirements, and Linux musl proves native static or static-PIE execution with no PT_INTERP and no DT_NEEDED",
  "Required platform markers occur exactly once and wrong architecture, non-native execution, timeout, skip, missing tool, runner or setup, missing hash or linkage row, and process cleanup failure produce FAIL or BLOCKED rather than PASS",
  "The qualification path uses direct native release-artifact observations as primary evidence and does not credit a helper self-test, mutated synthetic report, debug binary, cross-build-only result, archive, installer, upload, signature, or publication",
  "The same exact SHA, workflow run and attempt records authoritative full, security and process suites, TCP 12 of 12 plus cleanup, UDP 12 of 12 plus cleanup, all three platform rows, test-budget milestone PASS, and zero blocking review roots without evidence splicing",
  "Qualification contract tests, formatting, ticket test-budget, diff checks, and the hosted fail-closed evidence summary pass; provider unavailability remains release BLOCKED and only a demonstrated product defect reopens a product ticket",
]
+++

# M3-T05: Qualify native release artifacts on the three required targets

## Outcome

把三目标“能 cross-build”升级为同一 SHA release binaries 的 native
config/lifecycle/linkage/hash 资格，并与 full/security/TCP+UDP interop evidence
fail-closed 汇合。

## In scope

- Existing GitHub Actions provider的three-target release build/native execution。
- Direct CLI/config/startup rollback/signal shutdown/rebind observations。
- Windows PE、GNU ELF/GLIBC、musl static/static-PIE linkage records和SHA-256。
- Exact-SHA/run/attempt evidence aggregation，missing/unavailable fail closed。

## Out of scope

- Product code、config/runtime/observability/binary harness implementation。
- Archive/installer/signing/upload/publication或remote release。
- Performance、RSS/tasks、10k idle、long soak。
- 新 platform、architecture 或 future topology features。

## Contract references

- `ADR-0006` fixed target/provenance/unavailable policy。
- `ADR-0016` outcome-first equivalent evidence。
- `ADR-0017` six-job provider/evidence convergence。
- `ADR-0023` operator/artifact compatibility。
- `ADR-0024` production lifecycle seam。
- `SPEC-0004` M3-MUST-09/10；`TEST-0004` release qualification。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | build manifest keyed by exact SHA and per-binary SHA-256 |
| 2 | native bounded process observation table per target |
| 3 | direct PE/ELF/linkage command output |
| 4 | fail-closed marker/evidence aggregator |
| 5 | workflow inspection proving direct artifact path/no self-test substitution |
| 6 | one same-SHA completion summary with full + 24 interop + 3 targets |
| 7 | local qualification contract + hosted final statuses |

Platform evidence是唯一 primary seam；local parser/self-test只能防止报告格式误接线。

## Validation commands

```powershell
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

Hosted candidate commands/profile由`TEST-0004`固定；必须在用户对exact target授权
remote mutation后才push/run/rerun。本票ready不构成该授权。

## Ownership and risks

- T05 implementation/integration等待T06，release等待T01～T03与T06；T04因
  review escalation deferred且由T06 replacement，不编辑product或m0-harness
  files。
- Runner/provider/setup unavailable 是 release BLOCKED，不可用旧run、local
  emulation、different SHA 或 self-test豁免。
- musl必须执行 native artifact并直接检查linkage；cross-build success不足。
- Generated logs/hashes/artifacts不提交仓库；workflow只保存可审计 CI evidence。

## Completion evidence

- **Branch/worktree and lineage:** ticket branch `codex/ticket/m3-t05` in
  `C:\project\ferrum2\.worktrees\m3-t05`; integration branch
  `codex/integration/m3` in
  `C:\project\ferrum2\.worktrees\_integration-m3`. Initial candidate
  `441b2903dcb4c35b69428a079308b10f1a874ebb`; sole repair/final ticket
  candidate `bba40d127dee29a719d6ea1d80fb10427149d890`; final cumulative
  qualified product SHA
  `d9e59d787c3fe78dfca778ee8a36668a45387368`.
- **Changed paths:** `.github/workflows/m0.yml`,
  `tests/platform/qualify_native.py`, and removal of superseded
  `tests/platform/check_config_no_side_effects.rs`. No product/runtime,
  protocol, crypto, dependency, unsafe, or control-plane path changed.
- **Reviews:** Architect full review at `441b2903...` returned `PASS`; QA full
  review returned `BLOCK` under stable major finding `QA-M3-T05-001`.
  The sole substantive repair budget was consumed `1/1`; same-reviewer QA
  targeted review at `bba40d12...` returned `PASS` and resolved the finding.
  No accepted review debt.
- **Local evidence:** qualification contract, native Windows lifecycle repair
  evidence, formatting, strict Clippy, diff, ownership, control-plane, review,
  integration, authoritative quick `5/5`, and authoritative full `6/6` gates
  all exited `0`. Ticket budget passed at code `12956`, tests `19870`, ratio
  `1.534`; the cumulative milestone budget later passed at code `12956`,
  tests `19861`, ratio `1.533`, delta code/tests `1242/627`, allowance `1362`.
- **Hosted evidence:** the first exact-SHA run `30472227257/1` at `bba40d12...`
  remains immutable failed evidence and is not spliced. Fresh descendant run
  `30494736004`, attempt `1`, event `push`, at exact `d9e59d78...` completed
  `success`; quality, MSRV, Windows MSVC, Linux GNU, Linux musl, interop, and
  final qualification all succeeded on that one SHA/run/attempt.
- **Authorization/publication:** local scope `AUTH-M3-T05-LOCAL-001` and exact
  remote scope `AUTH-M3-T05-REMOTE-001` were each consumed and revoked `1/1`.
  Later T07/T08 descendant pushes used their own exact one-use grants. No
  force-push, rerun, dispatch, remote `master` update, PR, tag, release,
  upload, signing, publication, ref deletion, or control-plane mutation
  occurred.
