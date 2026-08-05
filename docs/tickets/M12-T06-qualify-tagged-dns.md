---
id: M12-T06
milestone: M12
status: planned
depends_on: [M12-T05]
owns:
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M12-*.md
  - docs/milestones/M12-tagged-dns-resolution-and-proxy.md
  - docs/roadmap.md
  - docs/tickets/M12-T06-qualify-tagged-dns.md
---

# M12-T06 — Qualify tagged DNS

## Outcome

Qualify one exact M12 integration SHA with focused DNS evidence、all repository gates、three platforms、
existing SIP022 plus new DNS interoperability and separately authorized performance/resource evidence。

## Acceptance

- [ ] T01～T05 focused commands and serial Full/MSRV/docs/lifecycle pass on the accepted exact SHA；
      ticket-only evidence is not substituted。
- [ ] Rust 1.88、Windows MSVC、Linux GNU/musl、existing SIP022 TCP/UDP `12/12` each plus cleanup and
      direct/detoured CoreDNS/BIND DNS interoperability pass without SHA/run/attempt splicing。
- [ ] Schema 3 integrity passes and numeric footprint signals are accepted、reduced or honestly
      reforecast；blocking Architect/QA findings are zero。
- [ ] Only after separate explicit authorizations，one non-force push runs automatic qualification and
      one exact-SHA manual dispatch runs required performance/resource evidence。
- [ ] No rerun、second push/dispatch、PR、tag、package、release or publication is inferred。

## Validation

Run `TEST-0013` T06 focused reruns and its serial integration gate。Remote commands remain blocked until
the user grants exact authorization。

## Rollback / risk

Qualification evidence is immutable and exact-SHA bound。Any failed/partial provider result remains
visible；repair、rerun or new remote mutation requires a new approved scope。
