---
id: M7-T03
milestone: M7
status: todo
depends_on: [M7-T02]
owns:
  - bins/ferrum2-client/src/run.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M7-T03 — Compose tagged client roots

## Outcome

Build every validated SOCKS5 inbound and referenced Shadowsocks server as concrete client contexts
under the same process transaction，with aggregate TCP/UDP bounds and no runtime route selection。

## Acceptance

- [ ] Multiple SOCKS TCP listeners plus optional metrics prepare atomically and use the shared
      process connection admission owner established by T02。
- [ ] The client removes T01's fail-closed multi-inbound run guard only when every validated
      inbound/outbound is consumed by this transaction。
- [ ] The shared CLI transition row then expects both composed roles to reach occupied endpoints
      and fail closed as `startup.bind` without disturbing those endpoints。
- [ ] Every CONNECT/UDP ASSOCIATE captures only its inbound's resolved server context；a failed
      referenced server never falls back to a live sibling outbound，while shared-outbound mappings
      work from multiple listeners。
- [ ] Client UDP uses one process-wide session/byte manager and live-ID collision owner across all
      inbounds；existing eight-attempt collision、source pin、FRAG、bounds and shutdown rules remain。
- [ ] First/middle/metrics preparation、listener fatal、control/idle/I/O failure、graceful/forced
      shutdown and restart/rebind return listener/permit/task/session/socket/buffer owners to
      baseline。
- [ ] Legacy single client、SOCKS replies、TCP half-close and all three-method TCP/UDP behavior
      remain exact；tag is not logged or used as a metric label。
- [ ] No `Endpoint` interface、adapter registry/factory、route enum、new dependency or duplicated
      lifecycle policy is introduced。
- [ ] `TEST-0008` T03 commands、repository Full、MSRV、ticket budget and blocking Architect/QA
      review pass on one exact candidate。

## Validation

Run `TEST-0008` T03 commands, then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores the single client root while leaving T01/T02 independently valid。Do not solve
mapping with per-flow tag lookup or duplicate one full `ClientContext` owner graph per listener。
