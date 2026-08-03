---
id: M8-T02
milestone: M8
status: todo
depends_on: [M8-T01]
owns:
  - bins/ferrum2-client/src/run.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M8-T02 — Route client TCP flows and UDP datagrams

## Outcome

Consume the compiled route table in the existing client composition so SOCKS TCP flows and each
valid UDP datagram select their configured Shadowsocks outbound with no fallback and bounded
control-owned UDP legs。

## Acceptance

- [ ] Client removes T01's routed-run guard only after listener inbound IDs and the complete
      outbound vector feed one shared route interface。
- [ ] TCP selects after SOCKS target validation and before server connect/write；overlap/final and
      unavailable-selected-server rows prove stable selection and no sibling attempt。
- [ ] One UDP association routes different targets to different server endpoints，with one
      application socket、one upstream socket、one manager handle/fixed buffer set and lazy
      per-activated-endpoint `UdpClientSession`/live ID。
- [ ] Wrong/inactive response source or wrong leg cannot authenticate/commit/refresh/forward；
      duplicate endpoint tags share a leg and unused outbounds create none。
- [ ] Existing source pin、FRAG/bounds、reservation-before-materialize/commit、association/replay、
      aggregate bytes/sessions/IDs、idle/cancel/fatal/forced/rebind semantics remain exact。
- [ ] No route trait、Endpoint、adapter registry/factory、new dependency/config setting、fallback
      or tag/destination telemetry is introduced。
- [ ] `TEST-0009` T02、repository Full、MSRV、ticket Budget and blocking Architect/QA review pass
      on one exact candidate。

## Validation

Run `TEST-0009` T02 commands，then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores the client routed-run guard while leaving T01 config/core independently valid。
Do not pin the association to its first route or allocate one socket/buffer set per outbound。
