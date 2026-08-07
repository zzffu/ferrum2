---
id: M13-T05
milestone: M13
status: done
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

- [x] The egress module owns UDP prepare、activate、reserve、nested encode、authenticated accept、commit、
      cancel/drop/reap and exposes only the operations its two consumers need。
- [x] SOCKS static/routed/selector selection grain、chain bounds、all-layer validation-before-mutation、
      replay/binding and current capacity owners remain exact。
- [x] Same server/equal snapshot reuses one healthy idle association；different plan/order、selector
      switch、I/O/auth failure、cancel、partial state or saturation cannot reuse it。
- [x] Internal DNS UDP remains independent from public UDP opt-in；UDP TC retains the same server/address/
      snapshot/deadline and never re-enters policy。
- [x] Failure and forced shutdown return all sessions/tasks/queues/buffers/live IDs and permit exact
      listener/hop/upstream rebind；no second manager、codec、pool ceiling or helper implementation appears。
- [x] `TEST-0014` T05、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0014` T05 commands，then repository Full。Use one table-driven red/green mutation matrix at the
association interface；reuse existing socket/session fixtures。

## Result

- Commit: `4d75d2ba0df8112517a3ab2e035aae1ac8123fe7`，fast-forward integrated。
- Review: Initial Architect/QA `BLOCK` on copied association-plan identity and a pool matrix that could
  not kill stale `reusable=true`；one bounded repair closed all four corresponding IDs，then targeted
  Architect and QA both returned `PASS` with no new finding。
- Notes: T05 focused and serial repository Full pass on the exact integration SHA；lifecycle is `1/1`
  in `127.26s` and docs pass。Ticket footprint integrity passes with ratio-only `WARN` and
  case/support/fixture delta `+122/0/0`；no helper、fixture、dependency or second data plane was added。

## Rollback / risk

Rollback restores the prior shared implementation and M12 pool as one unit。Primary risks are returning
partial state to the pool、changing mutation order or accidentally multiplying UDP capacity ownership。
