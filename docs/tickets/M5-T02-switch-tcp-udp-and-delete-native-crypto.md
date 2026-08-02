---
id: M5-T02
milestone: M5
status: active
depends_on: [M5-T01, M5-T01R]
owns:
  - Cargo.toml
  - Cargo.lock
  - crates/ferrum2-crypto/Cargo.toml
  - crates/ferrum2-crypto/src/lib.rs
  - crates/ferrum2-crypto/tests/**
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M5-T02 — Switch TCP/UDP and delete native crypto

## Outcome

Route the existing `ferrum2-crypto` public seam through patched
`shadowsocks-crypto` for all three methods and both transports, then delete the replaced
local cipher/KDF implementation and unused product dependencies in the same ticket.

## Acceptance

- [ ] Existing public types/traits/methods/error text and all downstream callers compile;
      `crates/ferrum2-shadowsocks/src/**` and schema/config behavior are unchanged.
- [ ] TCP and UDP KAT/composite fixtures are byte-exact for three methods; all existing
      negative, replay, binding and mutation-order tests pass.
- [ ] TCP u96le and UDP u64 exhaustion, commit-on-success, authentication failure,
      caller-buffer and zeroization semantics satisfy SPEC-0006.
- [ ] Product normal graph has one cipher/KDF backend. Old KDF/cipher code, direct
      primitive implementation edges, fallback and switches are absent.
- [ ] Only genuinely independent KAT oracle dependencies remain dev-only; lock and
      dependency/license policy describe the exact final graph.
- [ ] Focused commands, Quick/Full, ticket budget and blocking Architect/QA review pass.

## Validation

Run the exact T02 commands in `docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`,
then the repository Full commands before integration.

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / blocker

Do not integrate a partial transport switch. If the atomic candidate cannot preserve
the contract, keep M5 blocked on its pre-T02 integration base; do not add a dual backend
or runtime/feature fallback.

Execution resumed after accepted M5-T01R commit
`831388a3801cdec734e68ecc461c4c3f23ede8db` added the checked owner constructor for
the existing public raw TCP subkey seam.
