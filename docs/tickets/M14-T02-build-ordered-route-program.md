---
id: M14-T02
milestone: M14
status: todo
depends_on:
  - M14-T01
owns:
  - Cargo.lock
  - Cargo.toml
  - crates/ferrum2-core/Cargo.toml
  - crates/ferrum2-core/src/route.rs
  - crates/ferrum2-core/src/route/**
  - crates/ferrum2-core/src/selector.rs
  - crates/ferrum2-core/tests/route_program.rs
  - crates/ferrum2-core/tests/selector_contract.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M14-T02 — Build the ordered route program

## Outcome

Replace the one-shot ordinary matcher implementation with one protocol-neutral、bounded ordered program
and reusable egress graph while preserving every legacy `RouteTable` path and selector/plan contract。

## Acceptance

- [ ] Core exposes one small generic ordered-program interface with private monotonic cursor、immutable
      original context、mandatory final and at most 64 evaluations。
- [ ] Exact/suffix domain、IP/CIDR、port/range、legacy target and generic protocol-key matcher semantics
      satisfy SPEC-0015；exact `ipnet 2.12.1` is the only dependency activation。
- [ ] `RouteTable` compatibility methods delegate to the same implementation；no parallel ordinary
      `ActionTable` engine remains in product use。
- [ ] Terminal-time selector resolution、during/after-switch behavior、plan allocation/order/redaction and
      no policy re-entry remain exact。
- [ ] Core contains no concrete protocol/config/runtime types and server scalar selection cannot accept a
      multi-hop graph。
- [ ] T02 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-core --test route_program --locked
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-core --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo clippy -p ferrum2-core --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes the new program/direct dependency and restores the legacy implementation。Highest risk
is maintaining two subtly different engines；architecture evidence must make that state unmergeable。
