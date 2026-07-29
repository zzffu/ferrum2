+++
id = "M3-T02"
title = "Stabilize redacted tracing and metric identity"
milestone = "M3"
status = "ready"
priority = "P0"
risk = "high"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-observability/**",
]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "JSON tracing emits only the approved timestamp, level, event, role, transport, stage, outcome, optional reason, process-local numeric session_id, duration_ms, and bytes fields with closed categories and configured level filtering",
  "Secrets, raw or decoded configuration, keys, salts, nonces, wire identities, source, peer, target, destination, free-form messages, and free-form errors cannot enter an accepted trace record even through a direct tracing call",
  "The seven TCP and seven UDP metric base families retain their exact Prometheus counter or gauge types, label keys, HELP meaning, deterministic exposition, and counter _total sample convention",
  "Existing metric families cannot be removed or repurposed and all labels remain closed and bounded; one thousand distinct destinations and secret or identity sentinels cannot change series identity",
  "The API permits later additive closed trace categories or metric families without treating the current role, transport, stage, reason, inbound, direction, or outcome value set as all future product topology",
  "Focused metrics and tracing tests, strict Clippy, formatting, ticket test-budget, and diff checks pass without edits outside this ticket's ownership",
]
+++

# M3-T02: Stabilize redacted tracing and metric identity

## Outcome

把当前 trace 与 metric identity/meaning 固定成可升级的 operator contract，同时
保持 closed-cardinality、secret redaction 与未来 additive observability 空间。

## In scope

- Exact JSON field allowlist、closed category/value encoding和level filtering。
- Exact fourteen-family name/type/label/help/sample semantics。
- Secret/destination/identity/free-form injection sentinels。
- Additive extension boundary that does not repurpose existing identity。

## Out of scope

- Metrics HTTP listener lifecycle或binary error printing。
- 新 dashboard、alert、collector、destination/method labels或new product features。
- 改变 current TCP/UDP accounting semantics。

## Contract references

- `ADR-0023` stable traces/metrics和redaction boundary。
- `SPEC-0004` M3-MUST-04/05。
- `TEST-0004` T02 product commands与existing-table economy。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | existing closed JSON field/category table |
| 2 | one trace injection/redaction sentinel table |
| 3 | existing exact family/type/label/sample table |
| 4 | destination and UDP secret/identity series table |
| 5 | public closed-type/API contract inspection plus additive row |
| 6 | exact ticket gates and budget report |

Observability library tests是最小 seam；本票不需要启动二进制或 metrics listener。

## Validation commands

```powershell
cargo test -p ferrum2-observability --test metrics_contract --test tracing_contract --locked
cargo clippy -p ferrum2-observability --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T02 与 T01/T03 disjoint；不编辑 config、runtime、binary 或 process harness。
- Stable 是 identity/type/keys/meaning，不是冻结 enum implementation layout或
  禁止 additive family/category。
- Free-form tracing calls仍可存在于 dependency ecosystem，但 closed subscriber
  boundary不能采纳它们。

## Completion evidence

Filled by the Team Lead after integration:

- Candidate and integrated commit:
- Full/targeted review records and stable finding IDs:
- Test-budget result:
- Accepted review debt:
