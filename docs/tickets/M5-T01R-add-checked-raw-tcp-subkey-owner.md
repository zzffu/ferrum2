---
id: M5-T01R
milestone: M5
status: done
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

- [x] `TcpCipher::try_from_subkey` accepts only the three standard v2 methods and exact
      method key widths, performs no KDF, and returns the existing zeroizing owner.
- [x] The PSK-plus-salt constructor reuses the new primitive-key path after exactly one
      BLAKE3 KDF; private primitive modules remain private.
- [x] Compact vendor tests prove PSK/salt and pre-derived construction are byte-equal
      and reject invalid methods and widths.
- [x] `FERRUM_PATCH.md` records the additional checked API; provenance, features,
      dependencies, wire behavior and T02 product sources are unchanged.
- [x] Focused commands, Quick, ticket budget and blocking Architect/QA review pass.

## Validation

Run the vendored v2 tests and T01 focused commands from TEST-0006, then the repository
Quick commands in `docs/agents/milestone-workflow.md`.

## Result

- Commit: `831388a3801cdec734e68ecc461c4c3f23ede8db` (fast-forwarded unchanged to
  integration).
- Review: Architect `PASS`; QA `PASS`; zero findings on the exact commit.
- Notes: The three-method differential and negative test passed in an isolated vendor
  tree. Root Focused and Quick passed after integration; ticket budget returned
  `PASS_HOLD` with ticket debt `0` and anchor debt `108`.

## Rollback / blocker

This repair must remain a two-file vendor-only commit. If it cannot provide the raw
subkey owner without a second backend or public API change, M5 remains blocked before
the atomic T02 switch.
