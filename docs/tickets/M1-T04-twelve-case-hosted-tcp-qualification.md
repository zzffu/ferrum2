+++
id = "M1-T04"
title = "Expand hosted TCP qualification to twelve fail-closed cases"
milestone = "M1"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M1-T01"]
review_blocked_by = []
integration_blocked_by = ["M1-T01", "M1-T02", "M1-T03"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "tests/m0-harness/Cargo.toml",
  "tests/m0-harness/src/bin/m0_qualification.rs",
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/src/qualification/**",
  "tests/m0-harness/tests/qualification_contract.rs",
  "tests/interop/**",
  ".github/workflows/**",
]
spec = "docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md"
test_plan = "docs/test-plans/TEST-0002-m1-complete-tcp-methods-and-interop.md"
acceptance = [
  "M1-INT-001 through M1-INT-012 cover each method, pinned reference, and direction tuple exactly once in the TEST-0002 order with no dynamic discovery or waived row",
  "The existing sing-box 1.13.14 and shadowsocks-rust 1.24.0 version, commit, asset size, SHA-256, safe extraction, version-output, and black-box license policies are verified before their cases run",
  "Every case has independent temp, ports, children, absolute deadlines, bounded redacted capture, distinct bidirectional payload comparison, ADR-0014 ordered clean-EOF convergence, and cleanup",
  "Reference setup failure marks that reference's six rows FAIL under one canonical root while the other six remain runnable; case panic, timeout, payload, EOF, cleanup, missing, skipped, or nonzero result cannot produce PASS",
  "The qualification entry rejects before network or child activity unless the checkout is clean GitHub Actions Linux at exact GITHUB_SHA, and exit zero requires an explicit twelve-line 12-of-12 PASS summary plus cleanup",
  "Local quick/full, all-features, all-targets, and MSRV compile and lint the Cargo-managed non-test entry but never execute it, download references, open qualification sockets, or spawn external processes",
  "After separate authorization, one exact integrated SHA and one complete run/attempt reports quality, Rust 1.85 MSRV, Windows MSVC, Linux GNU, Linux musl, and M1 12-of-12 interoperability success; missing or unavailable evidence is BLOCKED rather than waived",
]
+++

# M1-T04: Expand hosted TCP qualification to twelve fail-closed cases

## Outcome

把 M0 四案 deep qualification 扩展为 TEST-0002 固定的 12-cell matrix，并保持
local/external seam、exact-SHA guard、failure continuation 与薄 CI profile。

## In scope

- 12 stable case definitions、method-correct synthetic configs/payloads。
- pinned reference provisioning reuse、six-row setup-root aggregation。
- per-case payload/EOF/deadline/capture/cleanup 与 12/12 summary。
- Cargo-managed non-test qualification manifest/entry。
- thin GitHub quality/MSRV/三平台/interop orchestration。
- one separately authorized exact-SHA hosted run as release evidence。

## Out of scope

- product crypto/protocol/config/runtime repair owned by T01–T03。
- reference upgrade、source vendoring、binary/artifact redistribution。
- local execution of qualification/reference/network。
- new YAML self-parser、case-count grep/filter、cache dependency、publication。
- M3 final platform qualification、M4 performance。

## Contract references

- `ADR-0006` reference/provenance/platform outcomes。
- `ADR-0014` external EOF evidence boundary。
- `ADR-0017` local/hosted thin qualification seam。
- `SPEC-0002` M1-AC-07/08。
- `TEST-0002` stable case matrix 与 release failure semantics。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | pure case-plan table asserts exact 12 unique tuples/IDs |
| 2 | existing pin/provision policy against `versions.toml` |
| 3 | one hosted row schema/driver path reused for every case |
| 4 | pure aggregation/failure-continuation mutation table |
| 5 | exact-SHA guard + hosted 12-line report/exit |
| 6 | Cargo metadata + local authoritative gates without entry execution |
| 7 | one complete GitHub run/attempt bound to exact integrated SHA |

hosted execution 是唯一 external compatibility evidence；pure state tests 只证明
plan/aggregation，不能冒充 reference process result。

## Validation commands

```powershell
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo metadata --no-deps --format-version 1 --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

本机禁止运行 `m0-qualification`。hosted command、push、workflow dispatch/rerun
只有在用户对 exact ref/SHA 另行授权后由 Team Lead 执行。

## Ownership and risks

- T04 可在 T01 done 后实现 case/profile model，与 T02 disjoint；在 T03 integrated
  前不得集成或声明 runnable product qualification。
- T04 不编辑 local_support 或 T03 named tests；harness manifest 是 T04 唯一 writer，
  只能使用 T01 已批准的 root workspace dependencies。
- 一个 reference setup failure 是六案共同 root，不是六个独立 root；另一 reference
  cases 继续运行。
- 旧 M0 run、不同 SHA/run 或部分 success 永不拼接为 M1 evidence。

## Completion evidence

- Branch/worktree/candidate: `codex/ticket/m1-t04`,
  `C:\project\ferrum2\.worktrees\m1-t04`,
  `b7a69899e4053e78fe8824e2cd9215b9d232e106`; product integration commit
  `fba23ca0b628bd6935d0977e3d9df7836b957e78`.
- Reviews: Architect and QA full reviews on the exact candidate both `PASS`;
  no stable finding, targeted review, or repair round.
- Local candidate validation: qualification binary build, pure
  `qualification_contract` 10/10, locked metadata, fmt, ticket budget, and
  `git diff --check` all exited 0. The non-test qualification entry was not
  executed.
- Integration validation on `fba23ca`: binary build; authoritative quick
  fmt/check/tests; authoritative full fmt/Clippy/all-feature tests/docs;
  workflow validation and `git diff --check` all exited 0.
- Hosted run ID/attempt/SHA and 12 case results: **not produced**. No external
  reference was downloaded, started, or contacted. Same-run/attempt exact-SHA
  12/12 evidence remains a separately authorized release qualification gate.
- Test budget: ticket gate `PASS`, code `7386`, tests `15216`, ratio `2.060`;
  baseline `7031/14707/2.092`; delta `+0/+120`, allowance `120`.
- Accepted review debt: none for T04. Push/publish: none.
