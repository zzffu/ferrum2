---
id: M8-T03
milestone: M8
status: done
depends_on: [M8-T02]
owns:
  - bins/ferrum2-server/src/run.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M8-T03 — Route authenticated server TCP/UDP requests

## Outcome

Consume the same compiled route table in server composition so every authenticated TCP request and
UDP datagram selects a configured direct outbound identity before egress mutation，without
duplicating direct runtime owners。

## Acceptance

- [x] Server removes T01's routed-run guard only after every TCP/UDP request path consumes its
      listener inbound ID、network、validated target and selected outbound ID。
- [x] TCP selection occurs after authenticated request/replay admission and before direct connect/
      prefix forwarding；overlap/final/failure rows prove no retry。
- [x] UDP selection occurs after borrowed authentication/bounds and before replay/activity/session/
      queue/target commit；one session can choose different direct identities per datagram。
- [x] Existing cross-inbound binding、same-inbound roaming、generation/replay、response listener、
      aggregate owners and direct DNS-after-route behavior remain exact。
- [x] Equivalent direct tags create no duplicate eager socket/runtime/root；no generic outbound
      trait、Endpoint/factory/registry、new dependency or fallback is added。
- [x] `TEST-0009` T03、repository Full、MSRV、ticket Budget and blocking Architect/QA review pass
      on one exact candidate。

## Validation

Run `TEST-0009` T03 commands，then repository Full commands before integration。

## Result

- Commit: `4a1de3a3183d1235ac3808ae97caebc851f4c2b5`
- Review: Architect `PASS`；QA `PASS`，所有 full/targeted findings closed。
- Notes: Server `18/18`、runtime `17/17 + 5/5 + 13/13`、CLI `5/5`、Full、Rust
  `1.85`、ignored lifecycle `1/1`、Clippy/fmt/diff and Budget PASS；growth `749/840`，
  remaining `91`。Final repairs preserve pre-open versus prefix cancellation observability and use
  authenticated production-path poison rows without adding per-tag owners or telemetry。

## Rollback / risk

Rollback restores the server routed-run guard while retaining T01/T02。Pre-auth selection、
post-commit selection or an ignored outbound ID is blocking。
