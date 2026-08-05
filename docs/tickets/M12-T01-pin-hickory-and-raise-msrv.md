---
id: M12-T01
milestone: M12
status: ready
depends_on: []
owns:
  - Cargo.toml
  - Cargo.lock
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/lib.rs
  - .github/workflows/m0.yml
  - tests/m0-harness/tests/workspace_policy.rs
---

# M12-T01 — Pin Hickory and raise MSRV

## Outcome

Add the minimum compiling `ferrum2-dns` workspace edge，pin the latest stable Hickory family exactly at
0.26.1 and raise the one workspace/CI MSRV contract from Rust 1.85.0 to 1.88.0。

## Acceptance

- [ ] `hickory-resolver/proto/server =0.26.1` are exact and resolver features are only Tokio、
      ring-backed DoT/DoH and WebPKI roots required by ADR-0031；normal graph has one Hickory family。
- [ ] Workspace and metadata MSRV are exactly 1.88.0；all CI commands use `+1.88.0` while
      `rust-toolchain.toml` remains 1.97.1。
- [ ] Workspace policy forbids system-config、DNSSEC/recursor、DoQ/DoH3、AWS-LC、duplicate Hickory/
      crypto providers and non-registry sources。
- [ ] License/provenance/lock review passes for Windows MSVC、Linux GNU and Linux musl；no product DNS
      behavior or config field is added in this ticket。
- [ ] `TEST-0013` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0013` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Rollback / risk

Rollback removes the new empty crate/dependency edge and restores Rust 1.85.0 everywhere。Primary risks
are hidden Hickory default features、a second TLS provider or an incomplete MSRV replacement。
