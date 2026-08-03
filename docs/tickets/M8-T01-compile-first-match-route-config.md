---
id: M8-T01
milestone: M8
status: done
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

- [x] The shared interface proves ordered first-match、AND/wildcards、exact IP/domain+port and
      mandatory final for `tcp|udp` without a trait、new crate or dependency。
- [x] Routed mode is tagged-only，mutually exclusive with `inbounds[].outbound`，bounded to 64
      rules and fully resolves inbound/outbound/final tags；static mode remains exact。
- [x] All matcher/target/count/reference/unreferenced/mixing negatives fail with the approved
      non-indexed redacted fields before subscriber/runtime/listener/buffer/task creation。
- [x] Validated configs own only compiled IDs/table；binary callers never parse operator strings。
- [x] `--check-config` accepts routed positives。Normal routed run remains temporarily fail-closed
      as existing `startup.protocol` for each uncomposed role，while static/legacy run is unchanged。
- [x] `TEST-0009` T01、repository Quick、ticket Budget and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0009` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: `876da7e13c37aaf4e316848b13cf0a8f7cb8673b`
- Review: full Architect/QA `BLOCK` closed by one bounded repair；targeted Architect
  `PASS_WITH_NOTES` and QA `PASS`，with no unresolved finding。
- Notes: focused、Quick、Clippy/fmt、diff and exact integration Budget passed。Test growth `273`
  exceeds warning `240` but remains within the approved `220 + 80` T01/repair allowance；M8
  remaining is `567` and no independent evidence was deleted。

## Rollback / risk

One slice removes `[route]` parsing and the core route module，restoring M7 static-only behavior。
Do not leave an accepted route document that either binary ignores，and do not expose tag/target
values for operator convenience。
