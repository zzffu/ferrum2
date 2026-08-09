---
id: M15-T02
milestone: M15
status: done
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

- [x] ADR-0033/SPEC-0015/TEST-0015 distinguish ephemeral route/selector calculation from committed terminal
      mode、source、association、session/live ID、activity and send state。
- [x] One focused regression performs selector A → maximum+1 candidate drop → switch to B → valid candidate
      and proves the valid candidate uses B exactly once。
- [x] The rejected candidate has zero accepted activity、association/session/live-ID owners、target traffic
      and policy-terminal commitment。
- [x] Existing first-valid-datagram、later-selector-ignored、response-binding and cleanup evidence remains
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

- Commit: `fc617cda7dac8e8ebf46c676fae09d4a2dce9bc1`；tree
  `a5218d72ed56c74f75f7b9384db33a7bc245383c`；parent/base
  `32342cb04d52ec42ea126744ce93968803f2c834`。
- Review: Architect and QA both `PASS_WITH_NOTES`；zero blocker/major/minor。`M15-T02-N01` and
  `QA-M15-T02-N01` accept the existing `socks.rs` file-size signal；`QA-M15-T02-N02` records one outer
  124-second command timeout followed by an unchanged exact 131.2-second workspace `PASS`。
- Footprint: integrity `PASS`；code/tests `25586/45012`，ratio `1.759243 PASS`；case/support/fixture
  `39263/5152/597`，delta `+3/0/0`。Numeric `REVIEW_REQUIRED` is accepted because the sole existing
  association regression gained three distinct case lines with no product、helper、support、fixture or
  harness growth。
- Notes: RED failed at the old A receive timeout；GREEN focused `1/1`、architecture `18/18` and workspace
  passed。Primary integration reran focused、architecture、footprint and diff checks successfully。No remote
  action was taken。

## Rollback / risk

Rollback removes one regression and restores the older over-strong wording。The risk is accidentally
changing accepted SOCKS UDP routing while trying to document existing mutation ordering；any product diff
requires a red test and explicit Architect/QA review。
