+++
id = "M3-T01"
title = "Preserve the schema v1 cohort without freezing current topology"
milestone = "M3"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-config/**",
  "tests/fixtures/config/**",
  "tests/m0-harness/tests/architecture.rs",
]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "One table proves every M3 client and server schema v1 required section, current default, accepted range, three method key width, UDP enabled or disabled choice, logging level, and optional metrics behavior as normalized values without retaining or printing secret input",
  "Committed synthetic preserved-cohort fixtures and explicit boundary rows continue to load unchanged while missing, unknown, oversized, malformed, wrong-version, invalid endpoint, invalid range, and noncanonical or wrong-length PSK rows retain the stable redacted config error category and field semantics",
  "The compatibility guard records the all-v0.x plus successor-after-12-months-and-two-stable-minors-with-prior-notice policy as an ongoing release obligation and does not falsely claim that elapsed time is proven at M3 close",
  "Schema selection remains explicit and fail closed with no heuristic fallback, automatic rewrite, or silent reinterpretation; tests permit later optional v1 additions and safe endpoint or value widening when omission preserves the cohort",
  "Architecture tests preserve the one-way dependency and deep-module boundaries but stop asserting that the current ten members, current targets, single listen or server, IPv4 validated endpoint types, or two binary roots exhaust future product topology",
  "Focused config and architecture tests, strict Clippy, formatting, ticket test-budget, and diff checks pass without edits outside this ticket's ownership",
]
+++

# M3-T01: Preserve the schema v1 cohort without freezing current topology

## Outcome

把当前合法 v1 文件及 effective values 变成可执行升级 cohort，同时移除把现有
workspace/endpoint/composition 误写成永久拓扑的 architecture assertions。

## In scope

- Current client/server schema shapes、defaults/ranges、method/PSK widths。
- Preserved synthetic fixture/effective-value table和negative redaction rows。
- Explicit schema-selection/evolution direction与compatibility policy guard。
- Dependency/deep-module architecture checks that are non-exhaustive for future
  topology。

## Out of scope

- CLI process/run errors、binary resources或observability。
- 实际增加 IPv6 operator endpoint、multi-inbound/outbound、routing、DNS、
  transparent inbound、TUN 或 schema v2。
- Future release time-window closeout。

## Contract references

- `ADR-0023` compatibility window、v1 evolution和topology boundary。
- `SPEC-0004` M3-MUST-01/02。
- `TEST-0004` T01 product commands与fixtures economy。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | existing `config_contract` role/default/boundary table |
| 2 | preserved fixtures + one categorized invalid table |
| 3 | version-policy contract row tied to cohort fixtures |
| 4 | explicit version/unknown/additive evolution table |
| 5 | `architecture` dependency/deep-boundary assertions |
| 6 | exact ticket gates and budget report |

同一 config table 同时证明 defaults、ranges与methods；不得按 field 新建 test file。

## Validation commands

```powershell
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-config --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T01、T02、T03 是 disjoint initial frontier；本票不编辑 binary/process tests、
  Cargo manifests、runtime 或 observability。
- Preserved cohort 是 M3 close parser实际接受集合；fixture 是 representative
  guard，不能用 fixture list 缩窄“全部合法配置”的合同。
- 允许未来 widening 不等于 M3 要实现 widening。

## Completion evidence

- Candidate `001047e895726debef04b31d781aa1eee73c24a9`; integrated as
  `540c5fb9a2be648e1c3fbcddfb6f66cc3d581747` in wave tip
  `da8fa58e0f50dda1637e3a2b205e6f34332a5bec`.
- Full Architect and QA reviews: PASS at the candidate SHA; no targeted round
  and no finding ID.
- Ticket test budget: PASS, code `11714`, tests `19182`, ratio `1.638`
  against baseline `1.642`.
- Accepted review debt: none.
