---
id: M8-T02
milestone: M8
status: done
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

- [x] Client removes T01's routed-run guard only after listener inbound IDs and the complete
      outbound vector feed one shared route interface。
- [x] TCP selects after SOCKS target validation and before server connect/write；overlap/final and
      unavailable-selected-server rows prove stable selection and no sibling attempt。
- [x] One UDP association routes different targets to different server endpoints，with one
      application socket、one upstream socket、one manager handle/fixed buffer set and lazy
      per-activated-endpoint `UdpClientSession`/live ID。
- [x] Wrong/inactive response source or wrong leg cannot authenticate/commit/refresh/forward；
      duplicate endpoint tags share a leg and unused outbounds create none。
- [x] Existing source pin、FRAG/bounds、reservation-before-materialize/commit、association/replay、
      aggregate bytes/sessions/IDs、idle/cancel/fatal/forced/rebind semantics remain exact。
- [x] No route trait、Endpoint、adapter registry/factory、new dependency/config setting、fallback
      or tag/destination telemetry is introduced。
- [x] `TEST-0009` T02、repository Full、MSRV、ticket Budget and blocking Architect/QA review pass
      on one exact candidate。

## Validation

Run `TEST-0009` T02 commands，then repository Full commands before integration。

## Result

- Commit: `ff9070c427bf456edbe3051d4f8781bb65c136c0`
- Review: initial Architect/QA `BLOCK`；one bounded repair；targeted Architect/QA
  `PASS_WITH_NOTES` with all findings resolved and no new blocker。
- Notes: client `29/29`、related protocol/runtime `141`、CLI `5/5`、Full、Rust 1.85、
  lifecycle `1/1`、Clippy/fmt/diff and Budget PASS。Budget growth is `659/840` with `181`
  remaining；the ticket warning records `386 > 240` required test lines。The first lifecycle shell
  wrapper timed out before the unchanged exact command passed in `131.12s` with a sufficient
  wrapper deadline。

## Rollback / risk

Rollback restores the client routed-run guard while leaving T01 config/core independently valid。
Do not pin the association to its first route or allocate one socket/buffer set per outbound。
