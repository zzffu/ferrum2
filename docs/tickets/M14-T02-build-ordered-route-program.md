---
id: M14-T02
milestone: M14
status: done
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

- [x] Core exposes one small generic ordered-program interface with private monotonic cursor、immutable
      original context、mandatory final and at most 64 rule inspections。
- [x] Exact/suffix domain、IP/CIDR、port/range、legacy target and generic protocol-key matcher semantics
      satisfy SPEC-0015；exact `ipnet 2.12.1` is the only dependency activation。
- [x] `RouteTable` compatibility methods delegate to the same implementation；no parallel ordinary
      `ActionTable` engine remains in product use。
- [x] Terminal-time selector resolution、during/after-switch behavior、plan allocation/order/redaction and
      no policy re-entry remain exact。
- [x] Core contains no concrete protocol/config/runtime types and server scalar selection cannot accept a
      multi-hop graph。
- [x] T02 focused、Quick、footprint integrity and diff gates pass。

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

- Commit: initial candidate `3dd8f6d45f1f359336412d8bf4a4fe7da8f9f523`；accepted repair and
  integration `c8a70ca213892e01a1c4ea97bf34f79a9feaf58a`。
- Review: initial Architect/QA `BLOCK` on `M14-T02-ARCH-001` and `M14-T02-QA-001/002`；one
  bounded two-file repair closed semantic legacy-target duplicates and both mutation-evidence gaps；
  targeted Architect/QA `PASS`，zero unresolved blocker。The dual-diagnosis escalation was not triggered。
- Footprint: integrity and ratio `PASS`，numeric `REVIEW_REQUIRED` accepted as advisory；code/tests
  `22156/40215`，case/support/fixture `34466/5152/597`，delta `+583/0/0`。The two
  existing-large-file signals extend the authoritative architecture/dependency harnesses；no helper、
  fixture or support growth，and ticket growth remains below `600`。
- Notes: route-program `4/4`，selector `7/7`，core `18/18`，architecture `16/16`，workspace
  policy `23/23` and repository Quick `379 passed / 5 ignored`；Clippy/fmt/check/build/diff all passed
  on integration。Exact no-default `ipnet 2.12.1` adds no package identity。No remote action was taken。

## Rollback / risk

Rollback removes the new program/direct dependency and restores the legacy implementation。Highest risk
is maintaining two subtly different engines；architecture evidence must make that state unmergeable。
