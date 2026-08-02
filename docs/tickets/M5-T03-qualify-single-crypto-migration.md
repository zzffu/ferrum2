---
id: M5-T03
milestone: M5
status: done
depends_on: [M5-T02]
owns:
  - docs/ci-status.md
  - docs/milestones/M5-shadowsocks-crypto-migration.md
  - docs/roadmap.md
  - docs/tickets/M5-T03-qualify-single-crypto-migration.md
---

# M5-T03 — Qualify the single-crypto migration

## Outcome

Qualify one exact integrated M5 commit with local Full/budget/review evidence and one
same-SHA hosted run covering MSRV, three platforms, TCP/UDP external interoperability
and the existing performance profile; record either complete PASS or M5 `blocked`.

## Acceptance

- [x] Exact integration candidate passes Full validation, milestone budget, final
      dependency/license/feature/unsafe/zeroize review and has zero blocking findings.
- [x] After separate explicit authorization, one push run/attempt for that exact SHA
      passes quality, Rust 1.85, all three native targets and final qualification.
- [x] The same run passes sing-box/shadowsocks-rust TCP `12/12` and UDP `12/12`, with
      complete cleanup and no result splicing.
- [x] The existing performance job records positive medians/ratio and passes resource,
      drain and cleanup; blocking performance review passes without a new numeric floor.
- [x] Missing, skipped, unavailable, unauthorized or failed required evidence records
      M5 as `blocked`; no old backend/fallback is restored.
- [x] No push/rerun/dispatch/PR/tag/release/publication occurs without its own explicit
      authorization.

## Validation

Run the exact integration/release commands in
`docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`.

## Result

- Accepted commit/run: `6ca043460f0a5233a0b39c9931b4f3f3a22f1cba`, automatic push
  run [`30743888837/1`](https://github.com/zzffu/ferrum2/actions/runs/30743888837).
- Review: final Architect and QA verdicts `PASS`; `QA-T03-001` closed, zero blocking
  findings. QA note `QA-T03-N01` is recorded in `docs/review-debt.md`.
- Notes: candidate tree `3474c7896bb8e3042e323991616418c2a93c76b4`, product commit
  `db4f100c35a2fc6615828b9aa176e8ede62eb855`. Local Full passed with `261`
  tests, `0` failures, `2` expected ignored cases and lifecycle `1/1`; Rust 1.85 and
  policy `26/26` passed. Milestone budget was `PASS_HOLD` at code `14066`, tests
  `20985`, ratio `1.491895`, debt `107`; the baseline was not ratcheted. Hosted
  qualification passed quality, MSRV, three platforms, TCP `12/12`, UDP `12/12`,
  cleanup and final aggregation. Performance recorded ferrum/reference medians
  `138726604/484138461`, ratio `0.286543242`, signed difference `-71.345675840%`,
  sessions `10000`, samples `180`, RSS windows `6/6` and drain `PASS`.

## Remote boundary

The authorized single non-force push was consumed by exact `6ca0434` and its automatic
run. No rerun, dispatch, second push, PR, tag, release or publication occurred or is
authorized. This documentation-only closeout does not replace the qualified SHA and
will not be pushed without new approval.
