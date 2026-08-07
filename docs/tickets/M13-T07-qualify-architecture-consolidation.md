---
id: M13-T07
milestone: M13
status: todo
depends_on: [M13-T06]
owns:
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M13-*.md
  - docs/milestones/M13-behavior-preserving-architecture-consolidation.md
  - docs/roadmap.md
  - docs/test-plans/TEST-0014-m13-behavior-preserving-architecture-consolidation.md
  - docs/tickets/M13-T07-qualify-architecture-consolidation.md
---

# M13-T07 — Qualify architecture consolidation

## Outcome

Qualify one exact M13 integration SHA with all focused preservation evidence、serial repository gates、
three platforms、existing SIP022/DNS interoperability and authorized performance/resource regression。

## Acceptance

- [ ] Every T01～T06 focused command passes on the accepted integration SHA；ticket-only results are not
      substituted。
- [ ] Serial Full、Rust 1.88 check/build/test、100+ lifecycle、Windows MSVC、Linux GNU/musl、SIP022
      TCP/UDP `12/12` each plus cleanup and CoreDNS/BIND DNS matrix pass without evidence splicing。
- [ ] Schema 3 integrity passes；numeric footprint movement/growth is explicitly dispositioned without
      deleting evidence。Final Architect/QA blocking findings are zero。
- [ ] After separate explicit authorizations only，one non-force push runs automatic qualification and
      one exact-SHA manual dispatch runs the existing M4 + M12 DNS performance/resource profile。
- [ ] Failed evidence remains visible；no unchanged-SHA rerun、second push/dispatch、PR、tag、package、
      release or publication is inferred。

## Validation

Run `TEST-0014` T07 serial integration gate exactly。Remote commands remain unrun until the user grants
separate exact-SHA push and manual-dispatch authorization。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Qualification evidence is immutable and exact-SHA bound。Any repair changes the SHA and requires fresh
review/validation plus new remote authorization；a docs-only closeout never replaces product identity。
