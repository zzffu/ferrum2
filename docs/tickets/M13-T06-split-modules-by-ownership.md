---
id: M13-T06
milestone: M13
status: ready
depends_on: [M13-T05]
owns:
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - bins/ferrum2-server/src/run/
  - bins/ferrum2-server/src/dns_egress.rs
  - crates/ferrum2-core/src/
  - crates/ferrum2-core/tests/
  - crates/ferrum2-config/src/
  - crates/ferrum2-config/tests/
  - tests/m0-harness/tests/architecture.rs
---

# M13-T06 — Split modules by ownership

## Outcome

Move the remaining client/server/core/config implementation and tests to their real owners so `run.rs`
is composition only，without changing any interface or behavior established by T02～T05。

## Acceptance

- [ ] Client separates process/context/SOCKS/egress/DNS/I/O/observation ownership；server separates
      process/TCP/UDP/DNS/I/O/observation ownership。Composition roots contain no protocol execution。
- [ ] Server UDP capability、reservation and commit ordering remains one reviewable seam；no server
      outbound abstraction is introduced。
- [ ] Core `route::*`/`selector::*` and config root re-exports/load/error paths remain compatible；all
      config cohorts and public control tests pass unchanged。
- [ ] Tests move with owners and keep independent negative/lifecycle evidence；no copied private path、
      third helper、fixture or second harness/data plane is added。
- [ ] Architecture guards prove dependency direction、owned snapshot uniqueness、DNS adapter restrictions、
      composition-root exclusions and unchanged workspace/dependency/unsafe state。
- [ ] `TEST-0014` T06、repository Full、100+ lifecycle、ticket footprint and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0014` T06 commands，repository Full and the ignored lifecycle command。This ticket moves
already-green behavior；any semantic change must return to the owning earlier interface ticket rather
than being hidden in mechanical movement。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback is a source-layout reversal only。Primary risks are module visibility expanding to keep tests
working and file movement obscuring a lifecycle/order change；review uses exact commits and moved-code
diff inspection。
