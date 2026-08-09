---
id: M15-T02
milestone: M15
status: ready
depends_on:
  - M15-T01
owns:
  - bins/ferrum2-client/src/run/socks.rs
  - docs/adr/ADR-0033-m14-ordered-route-program-and-protocol-sniffing.md
  - docs/specs/SPEC-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/test-plans/TEST-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
---

# M15-T02 — Prove UDP candidate commit ordering

## Outcome

Clarify and prove the existing M14 SOCKS UDP behavior before TUN reuses it：selected-plan lookup may be
temporary when calculating a chain-specific payload limit，but an over-limit candidate commits no terminal
state or resource；the next valid candidate re-evaluates and sees the current selector。No runtime change is
expected unless the focused regression first turns red。

## Acceptance

- [ ] ADR-0033/SPEC-0015/TEST-0015 distinguish ephemeral route/selector calculation from committed terminal
      mode、source、association、session/live ID、activity and send state。
- [ ] One focused regression performs selector A → maximum+1 candidate drop → switch to B → valid candidate
      and proves the valid candidate uses B exactly once。
- [ ] The rejected candidate has zero accepted activity、association/session/live-ID owners、target traffic
      and policy-terminal commitment。
- [ ] Existing first-valid-datagram、later-selector-ignored、response-binding and cleanup evidence remains
      green。If the new test already passes，the ticket changes only contract text and the existing test body。

## Validation

```powershell
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test --workspace --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback removes one regression and restores the older over-strong wording。The risk is accidentally
changing accepted SOCKS UDP routing while trying to document existing mutation ordering；any product diff
requires a red test and explicit Architect/QA review。
