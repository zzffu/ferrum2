---
id: M8-T01
milestone: M8
status: ready
depends_on: []
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/fixtures/config/*route*.toml
  - tests/m0-harness/tests/config_cli.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-server/src/run.rs
---

# M8-T01 — Compile bounded first-match route config

## Outcome

Add one runtime-neutral total route module and make both schema v1 loaders compile routed tagged
documents into resolved inbound/outbound IDs before any side effect，while preserving every
legacy/M7 static document。

## Acceptance

- [ ] The shared interface proves ordered first-match、AND/wildcards、exact IP/domain+port and
      mandatory final for `tcp|udp` without a trait、new crate or dependency。
- [ ] Routed mode is tagged-only，mutually exclusive with `inbounds[].outbound`，bounded to 64
      rules and fully resolves inbound/outbound/final tags；static mode remains exact。
- [ ] All matcher/target/count/reference/unreferenced/mixing negatives fail with the approved
      non-indexed redacted fields before subscriber/runtime/listener/buffer/task creation。
- [ ] Validated configs own only compiled IDs/table；binary callers never parse operator strings。
- [ ] `--check-config` accepts routed positives。Normal routed run remains temporarily fail-closed
      as existing `startup.protocol` for each uncomposed role，while static/legacy run is unchanged。
- [ ] `TEST-0009` T01、repository Quick、ticket Budget and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0009` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

One slice removes `[route]` parsing and the core route module，restoring M7 static-only behavior。
Do not leave an accepted route document that either binary ignores，and do not expose tag/target
values for operator convenience。
