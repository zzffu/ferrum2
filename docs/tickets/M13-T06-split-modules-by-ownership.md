---
id: M13-T06
milestone: M13
status: done
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

- [x] Client separates process/context/SOCKS/egress/DNS/I/O/observation ownership；server separates
      process/TCP/UDP/DNS/I/O/observation ownership。Composition roots contain no protocol execution。
- [x] Server UDP capability、reservation and commit ordering remains one reviewable seam；no server
      outbound abstraction is introduced。
- [x] Core `route::*`/`selector::*` and config root re-exports/load/error paths remain compatible；all
      config cohorts and public control tests pass unchanged。
- [x] Tests move with owners and keep independent negative/lifecycle evidence；no copied private path、
      third helper、fixture or second harness/data plane is added。
- [x] Architecture guards prove dependency direction、owned snapshot uniqueness、DNS adapter restrictions、
      composition-root exclusions and unchanged workspace/dependency/unsafe state。
- [x] `TEST-0014` T06、repository Full、100+ lifecycle、ticket footprint and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0014` T06 commands，repository Full and the ignored lifecycle command。This ticket moves
already-green behavior；any semantic change must return to the owning earlier interface ticket rather
than being hidden in mechanical movement。

## Result

- Commit: `c3bb625ba18305dec20518977e29d9d965ceeb4d`
- Review: targeted Architect `PASS`；targeted QA `PASS`；all three original ownership/evidence findings
  closed after one bounded repair and the required independent escalation。
- Notes: Integration T06 focused and serial Full passed，including architecture `15/15`、the preserved
  four-package cohort `94`、workspace `372 passed / 5 ignored`、TCP/UDP DNS E2E `1/1` each、100+
  lifecycle `1/1` and docs。Footprint integrity passed；ticket case/support/fixture movement
  `-762/0/0` is owner-file reclassification with the `92/92` test-name multiset and assertion inventory
  preserved。The advisory `changed_test_file_size` review remains visible for T07；no product behavior、
  dependency、fixture、harness or remote action was added。

## Rollback / risk

Rollback is a source-layout reversal only。Primary risks are module visibility expanding to keep tests
working and file movement obscuring a lifecycle/order change；review uses exact commits and moved-code
diff inspection。
