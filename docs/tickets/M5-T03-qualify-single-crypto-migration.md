---
id: M5-T03
milestone: M5
status: active
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

- [ ] Exact integration candidate passes Full validation, milestone budget, final
      dependency/license/feature/unsafe/zeroize review and has zero blocking findings.
- [ ] After separate explicit authorization, one push run/attempt for that exact SHA
      passes quality, Rust 1.85, all three native targets and final qualification.
- [ ] The same run passes sing-box/shadowsocks-rust TCP `12/12` and UDP `12/12`, with
      complete cleanup and no result splicing.
- [ ] The existing performance job records positive medians/ratio and passes resource,
      drain and cleanup; blocking performance review passes without a new numeric floor.
- [ ] Missing, skipped, unavailable, unauthorized or failed required evidence records
      M5 as `blocked`; no old backend/fallback is restored.
- [ ] No push/rerun/dispatch/PR/tag/release/publication occurs without its own explicit
      authorization.

## Validation

Run the exact integration/release commands in
`docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`.

## Result

- Accepted commit/run: —
- Review: —
- Notes: —

## Blocker

Hosted qualification requires a future exact-SHA push authorization. Feature planning
and local execution do not grant it.
