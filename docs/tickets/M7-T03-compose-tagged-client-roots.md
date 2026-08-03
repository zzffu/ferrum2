---
id: M7-T03
milestone: M7
status: done
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

- [x] Multiple SOCKS TCP listeners plus optional metrics prepare atomically and use the shared
      process connection admission owner established by T02。
- [x] The client removes T01's fail-closed multi-inbound run guard only when every validated
      inbound/outbound is consumed by this transaction。
- [x] The shared CLI transition row then expects both composed roles to reach occupied endpoints
      and fail closed as `startup.bind` without disturbing those endpoints。
- [x] Every CONNECT/UDP ASSOCIATE captures only its inbound's resolved server context；a failed
      referenced server never falls back to a live sibling outbound，while shared-outbound mappings
      work from multiple listeners。
- [x] Client UDP uses one process-wide session/byte manager and live-ID collision owner across all
      inbounds；existing eight-attempt collision、source pin、FRAG、bounds and shutdown rules remain。
- [x] First/middle/metrics preparation、listener fatal、control/idle/I/O failure、graceful/forced
      shutdown and restart/rebind return listener/permit/task/session/socket/buffer owners to
      baseline。
- [x] Legacy single client、SOCKS replies、TCP half-close and all three-method TCP/UDP behavior
      remain exact；tag is not logged or used as a metric label。
- [x] No `Endpoint` interface、adapter registry/factory、route enum、new dependency or duplicated
      lifecycle policy is introduced。
- [x] `TEST-0008` T03 commands、repository Full、MSRV and blocking Architect/QA review pass on one
      exact candidate；the failed ticket-budget ceiling is recorded below under the explicit
      T03/T04 user waiver and is not represented as a pass。

## Validation

Run `TEST-0008` T03 commands, then repository Full commands before integration。

## Result

- Commit: initial candidate `7f4258cac99b3e9168a568bc8f566b767c161bcf`；bounded repair and
  integrated product `b3f7ff8e6dad22d37f8fb95bc42c7e83c6834c72`。
- Review: initial Architect/QA both BLOCKED on missing composed UDP/byte/live-ID/listener-fatal
  evidence and collapsed accept errors。One bounded repair preserved original `io::Error` and added
  direct composed evidence；targeted Architect and QA reviews both PASS with every finding closed。
- Notes: exact repair client `27/27`、CLI `5/5`、focused suites、Clippy/fmt/diff、repository Full
  `6/6`、ignored lifecycle `1/1` and Rust 1.85 check/build/test PASS。The first MSRV workspace test
  hit the pre-existing Windows TCP-reserved-port to UDP-bind race (`WSAEACCES`)；the exact isolated
  row passed `1/1` and the unchanged authoritative command then passed。Budget remains honestly
  `BLOCKED reason=ratio_ceiling_exceeded`；the user explicitly waived T03/T04 budget blocking。

## Rollback / risk

Rollback restores the single client root while leaving T01/T02 independently valid。Do not solve
mapping with per-flow tag lookup or duplicate one full `ClientContext` owner graph per listener。
