+++
id = "M3-T05"
title = "Qualify native release artifacts on the three required targets"
milestone = "M3"
status = "ready"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M3-T04"]
review_blocked_by = []
integration_blocked_by = ["M3-T04"]
release_blocked_by = ["M3-T01", "M3-T02", "M3-T03", "M3-T04"]
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

- T05 implementation/integration等待T04，release等待T01～T04；不编辑product或
  m0-harness files。
- Runner/provider/setup unavailable 是 release BLOCKED，不可用旧run、local
  emulation、different SHA 或 self-test豁免。
- musl必须执行 native artifact并直接检查linkage；cross-build success不足。
- Generated logs/hashes/artifacts不提交仓库；workflow只保存可审计 CI evidence。

## Completion evidence

Filled by the Team Lead after integration:

- Candidate and integrated commit:
- Full/targeted review records and stable finding IDs:
- Test-budget result:
- Accepted review debt:
