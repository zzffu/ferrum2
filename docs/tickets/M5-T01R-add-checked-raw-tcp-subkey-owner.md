---
id: M5-T01R
milestone: M5
status: active
depends_on: [M5-T01]
owns:
  - vendor/shadowsocks-crypto/src/v2/tcp/mod.rs
  - vendor/shadowsocks-crypto/FERRUM_PATCH.md
---

# M5-T01R — Add checked raw TCP subkey owner

## Outcome

Close the T01/T02 interface gap with one checked no-KDF constructor that turns an
already-derived SIP022 TCP subkey into the existing vendored `TcpCipher` owner.

## Acceptance

- [ ] `TcpCipher::try_from_subkey` accepts only the three standard v2 methods and exact
      method key widths, performs no KDF, and returns the existing zeroizing owner.
- [ ] The PSK-plus-salt constructor reuses the new primitive-key path after exactly one
      BLAKE3 KDF; private primitive modules remain private.
- [ ] Compact vendor tests prove PSK/salt and pre-derived construction are byte-equal
      and reject invalid methods and widths.
- [ ] `FERRUM_PATCH.md` records the additional checked API; provenance, features,
      dependencies, wire behavior and T02 product sources are unchanged.
- [ ] Focused commands, Quick, ticket budget and blocking Architect/QA review pass.

## Validation

Run the vendored v2 tests and T01 focused commands from TEST-0006, then the repository
Quick commands in `docs/agents/milestone-workflow.md`.

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / blocker

This repair must remain a two-file vendor-only commit. If it cannot provide the raw
subkey owner without a second backend or public API change, M5 remains blocked before
the atomic T02 switch.
