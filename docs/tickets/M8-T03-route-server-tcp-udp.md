---
id: M8-T03
milestone: M8
status: ready
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

- [ ] Server removes T01's routed-run guard only after every TCP/UDP request path consumes its
      listener inbound ID、network、validated target and selected outbound ID。
- [ ] TCP selection occurs after authenticated request/replay admission and before direct connect/
      prefix forwarding；overlap/final/failure rows prove no retry。
- [ ] UDP selection occurs after borrowed authentication/bounds and before replay/activity/session/
      queue/target commit；one session can choose different direct identities per datagram。
- [ ] Existing cross-inbound binding、same-inbound roaming、generation/replay、response listener、
      aggregate owners and direct DNS-after-route behavior remain exact。
- [ ] Equivalent direct tags create no duplicate eager socket/runtime/root；no generic outbound
      trait、Endpoint/factory/registry、new dependency or fallback is added。
- [ ] `TEST-0009` T03、repository Full、MSRV、ticket Budget and blocking Architect/QA review pass
      on one exact candidate。

## Validation

Run `TEST-0009` T03 commands，then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores the server routed-run guard while retaining T01/T02。Pre-auth selection、
post-commit selection or an ignored outbound ID is blocking。
