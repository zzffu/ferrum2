---
id: M5-T01
milestone: M5
status: ready
depends_on: []
owns:
  - vendor/shadowsocks-crypto/**
  - Cargo.toml
  - Cargo.lock
  - crates/ferrum2-crypto/Cargo.toml
  - tests/m0-harness/tests/workspace_policy.rs
---

# M5-T01 — Pin and harden `shadowsocks-crypto`

## Outcome

Import the exact reviewed 0.7.0 source and apply only the controlled patch needed for
checked nonce/operation APIs, secret zeroization, AES-UDP header protection, and a
minimal safe v2 dependency graph. Add the exact no-default `v2` edge without switching
the ferrum backend yet.

## Acceptance

- [ ] Vendor provenance matches version, archive checksum, VCS commit and MIT LICENSE
      in ADR-0025; pristine-to-patch delta is bounded and independently reviewable.
- [ ] Selected product graph enables only `v2`; default/v1/v2-extra/reduced-round/ring/
      aws-lc are absent, and selected v2 has no unused `rand` or `unsafe` path.
- [ ] Patch exposes only the operations needed for checked TCP, AES-UDP header/body and
      ChaCha UDP; it owns no protocol/replay/config/runtime behavior.
- [ ] KDF temporaries and expanded secret state have explicit zeroization coverage.
- [ ] Exact resolved package/features/licenses are encoded in existing workspace policy;
      Rust 1.85.0 compiles the selected graph.
- [ ] Focused commands, ticket budget and blocking Architect/QA review pass.

## Validation

Run the exact T01 commands in `docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`,
then the repository Quick commands in `docs/agents/milestone-workflow.md`.

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / blocker

Before T02, this ticket may be reverted as one dependency import. After T02 there is no
old-backend fallback: an unclosed security/license/MSRV finding blocks M5 and requires a
forward patch or explicit superseding decision.
