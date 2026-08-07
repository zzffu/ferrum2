---
id: M13-T04
milestone: M13
status: ready
depends_on: [M13-T03]
owns:
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run/egress/mod.rs
  - bins/ferrum2-client/src/run/egress/tcp.rs
---

# M13-T04 — Extract client TCP egress

## Outcome

Put the existing ordered TCP chain implementation behind one concrete private client egress interface
used by both SOCKS CONNECT and DNS TCP-family detours。

## Acceptance

- [ ] `ClientEgressEngine` opens a caller-selected `EgressPlanSnapshot` and owns outbound preparation、
      chain traversal、connector/clock/random/deadline and nested flow lifetimes。
- [ ] The engine contains no route/selector policy or SOCKS ingress ownership；the DNS adapter holds the
      engine rather than full process/routing context。
- [ ] SOCKS direct/2-hop mixed-credential and DNS TCP/DoT/DoH detour rows use the same executor and retain
      exact snapshot、target nesting、deadline and no-fallback behavior。
- [ ] First/later-hop failure、half-close、cancel and abortive terminal release every layer/owner and do
      not report application success。
- [ ] DNS adapter imports no TCP implementation helper；no trait、factory、crate、dependency or detached
      bridge owner is added beyond the existing DNS egress seam。
- [ ] `TEST-0014` T04、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0014` T04 commands，then repository Full。Move each existing test with the executor and make it
red/green through the engine interface；do not test past the interface by exposing old helpers。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback reconnects both consumers to the prior helper only as one change。Primary risks are lifetime/
half-close drift and a DNS-only execution path surviving beside the shared engine。
