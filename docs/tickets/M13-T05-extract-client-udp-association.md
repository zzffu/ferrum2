---
id: M13-T05
milestone: M13
status: todo
depends_on: [M13-T04]
owns:
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run/egress/mod.rs
  - bins/ferrum2-client/src/run/egress/udp.rs
---

# M13-T05 — Extract the bounded client UDP association

## Outcome

Put SOCKS and DNS detoured UDP behind one bounded association implementation and make M12's idle reuse
identity explicitly `(first server, owned egress plan)`。

## Acceptance

- [ ] The egress module owns UDP prepare、activate、reserve、nested encode、authenticated accept、commit、
      cancel/drop/reap and exposes only the operations its two consumers need。
- [ ] SOCKS static/routed/selector selection grain、chain bounds、all-layer validation-before-mutation、
      replay/binding and current capacity owners remain exact。
- [ ] Same server/equal snapshot reuses one healthy idle association；different plan/order、selector
      switch、I/O/auth failure、cancel、partial state or saturation cannot reuse it。
- [ ] Internal DNS UDP remains independent from public UDP opt-in；UDP TC retains the same server/address/
      snapshot/deadline and never re-enters policy。
- [ ] Failure and forced shutdown return all sessions/tasks/queues/buffers/live IDs and permit exact
      listener/hop/upstream rebind；no second manager、codec、pool ceiling or helper implementation appears。
- [ ] `TEST-0014` T05、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0014` T05 commands，then repository Full。Use one table-driven red/green mutation matrix at the
association interface；reuse existing socket/session fixtures。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores the prior shared implementation and M12 pool as one unit。Primary risks are returning
partial state to the pool、changing mutation order or accidentally multiplying UDP capacity ownership。
