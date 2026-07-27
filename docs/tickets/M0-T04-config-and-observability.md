+++
id = "M0-T04"
title = "Implement typed configuration and bounded observability"
milestone = "M0"
status = "review"
priority = "P1"
blocked_by = ["M0-T02"]
owns = [
  "crates/ferrum2-config/src/**",
  "crates/ferrum2-config/tests/**",
  "crates/ferrum2-observability/src/**",
  "crates/ferrum2-observability/tests/**",
  "tests/fixtures/config/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "All ADR-0003 schema fields, defaults, ranges, unknown-field checks, canonical Base64 rules, and role-specific cross-field constraints have table-driven tests",
  "M0-OBS-001 passes for the fixed JSON field enums and sentinel redaction contract",
  "M0-OBS-002 passes for all seven metric families, exact typed labels, deterministic text encoding, and invariant series count across 1000 destinations",
  "Config validation returns role-specific types containing Aes128Psk without preserving raw TOML or secret strings and does not construct runtime resources",
]
+++

# M0-T04: Implement typed configuration and bounded observability

## Outcome

交付两个role-specific validated TOML types、structured tracing与typed Prometheus
registry/text encoder。CLI/process、runtime metrics socket与无副作用证明分别在T07、
T06/T07完成。

## Context

本票在T02后执行，因为config返回crypto-owned `Aes128Psk`；它仍可与T03并行。
observability不拥有global recorder、Tokio或listener task。

## In scope

- 1 MiB bounded UTF-8 read、Serde typed parse、全部semantic validation。
- strict canonical base64到`Aes128Psk`、secret-bearing parser/error redaction。
- newline JSON tracing initialization、closed field enums。
- explicit Prometheus registry、七项metric families与deterministic text encoding。
- valid/invalid synthetic config fixtures。

## Out of scope

- binary CLI/`main`/supervisor/listener创建与process E2E（T07）。
- metrics socket、HTTP bounds和lifecycle（T06）。
- protocol/runtime instrumentation call sites（T03/T06/T07）。
- CI provider或M3 final schema。
- 修改manifest/lock。

## Implementation notes and constraints

- offline parser/validator不得调用Tokio、bind、connect或install global subscriber。
- source parser message/raw TOML不得穿过operator error boundary。
- metrics registry显式传递；crate只编码text，不依赖Tokio、不bind且不自spawn。
- destination与自由error string不能成为trace field或metric label。

## Validation commands

```bash
cargo test -p ferrum2-config --locked
cargo test -p ferrum2-observability --locked
cargo test -p ferrum2-observability --test tracing_contract --locked
cargo test -p ferrum2-observability --test metrics_contract --locked
cargo clippy -p ferrum2-config -p ferrum2-observability --all-targets --all-features --locked -- -D warnings
cargo fmt -p ferrum2-config -p ferrum2-observability -- --check
```

## Risks

- TOML parser source error可能回显secret-bearing line；必须转换而非透传。
- global tracing/metrics初始化会污染并行测试并破坏ownership。
- arbitrary log filter/metric reason会造成不受控cardinality。

## Completion evidence

- Branch: `codex/ticket/m0-t04`
- Candidate: `e9c6b01e0947483dac25012f9d02f99823970827`
- Team Lead lineage/ownership/clean-worktree checks: PASS；10 additions，全部属于
  T04 ownership；无 manifest/lock/doc change
- Engineer gates: config 7/7、observability 5/5、focused tracing 2/2、focused
  metrics 3/3、strict Clippy/fmt/diff PASS
- Initial review: Architect **BLOCK**、QA **BLOCK**。Target-only filtering permits
  an external exact-target callsite to emit secret/destination/free-form fields
  through the closed NDJSON channel；`[server]` unknown-field table evidence is
  also missing。Candidate is not integrated；repair 1/2 active on the preserved
  worktree and may change only T04-owned source/tests。
- Integrated commit: pending
