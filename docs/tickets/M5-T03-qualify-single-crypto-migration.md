---
id: M5-T03
milestone: M5
status: blocked
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
- [x] Missing, skipped, unavailable, unauthorized or failed required evidence records
      M5 as `blocked`; no old backend/fallback is restored.
- [x] No push/rerun/dispatch/PR/tag/release/publication occurs without its own explicit
      authorization.

## Validation

Run the exact integration/release commands in
`docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`.

## Result

- Accepted commit/run: —
- Review: local-only exact candidate
  `816fa7b9a19a7c0f805280063dce837caa751c3a` received Architect `PASS` and QA
  local `PASS`; `QA-T03-001` remains a blocker because hosted evidence is absent.
- Notes: candidate tree `5d4040e0d213e3fbaf08503a714ad0b44f7482ce`, product parent
  `db4f100c35a2fc6615828b9aa176e8ede62eb855`. Local Full passed with `261`
  tests, `0` failures and `2` expected ignored cases; the exact ignored lifecycle
  gate passed `1/1`, Rust 1.85 and policy `26/26` passed, and milestone budget was
  `PASS_HOLD` at code `14066`, tests `20985`, ratio `1.491895`, debt `107`.
  Hosted status is `NOT RUN / UNAUTHORIZED`; run, attempt and job IDs are `—`.

## Blocker

Hosted qualification requires a future exact-SHA push authorization. Feature planning
and local execution do not grant it. No remote action or historical evidence splice
occurred, and `816fa7b9a19a7c0f805280063dce837caa751c3a` is not an accepted M5 close
SHA. This blocker record creates a docs-only descendant; after future authorization,
all local and hosted gates must be rerun against the then-current clean integration
HEAD in one exact-SHA evidence chain.
