+++
id = "M3-T04"
title = "Compose both binaries through the transactional supervisor"
milestone = "M3"
status = "blocked"
priority = "P0"
risk = "critical"
implementation_blocked_by = ["M3-T01", "M3-T02", "M3-T03"]
review_blocked_by = []
integration_blocked_by = ["M3-T01", "M3-T02", "M3-T03"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "bins/ferrum2-client/**",
  "bins/ferrum2-server/**",
  "tests/m0-harness/src/local_support/**",
  "tests/m0-harness/tests/cli_contract.rs",
  "tests/m0-harness/tests/config_cli.rs",
  "tests/m0-harness/tests/lifecycle_cycles.rs",
  "tests/m0-harness/tests/local_e2e.rs",
  "tests/m0-harness/tests/udp_local_e2e.rs",
]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "Both binaries preserve --config, --check-config, --help, --version and exit classes 0, 2, and 1; every non-usage configuration or run failure emits exactly one redacted diagnostic with its stable config or startup, runtime, or shutdown code while normal signal shutdown exits 0",
  "Configuration loading and complete semantic validation finish before subscriber or process-global state, Tokio runtime, listener, socket, metrics registry or endpoint, replay or session table, channel, buffer reservation, or task creation; check-config proves zero such resources",
  "Client and server adapt their required TCP, server UDP when enabled, and optional metrics roots to the reusable supervisor so every fallible root is prepared before any service polling and every preparation or activation failure rolls back all other roots",
  "Required listener, metrics root, supervisor child panic or join, and root terminal failures select one deterministic process cause, cancel all roots, and reap them, while protocol, target, queue, idle and relay failures remain affected-flow or session scoped",
  "External signal shutdown stops admission, preserves existing TCP half-close and admitted UDP behavior through the configured absolute grace deadline, force-cancels remaining work, emits bounded observability, and returns only after all production owners are reaped or shutdown.cleanup is reported",
  "One bounded production-used process table performs at least 100 startup, occupied proxy or metrics rollback, TCP and UDP root failure, graceful and forced shutdown, and restart or immediate rebind cycles for the current client and server adapters with no owner growth or leaked resource",
  "Current three-method TCP and UDP local product paths, UDP disabled behavior, CLI and config suites, strict Clippy, formatting, ticket test-budget, and diff checks pass without edits outside this ticket's ownership",
]

[blocker]
id = "ARC-M3-T04-004"
class = "code"
gate = "review"
root_cause = "After the sole substantive repair, a terminal UDP root error with live work can wait for ProcessCancellation::Forced before returning the error that would cause ProcessSupervisor to enter Fatal and broadcast Forced; forced shutdown also lacks a bounded fallback for an uncooperative root."
derivatives = ["ARC-M3-T04-001", "ARC-M3-T04-002", "QA-M3-T04-001"]
owner = "team_lead"
evidence = "Architect and QA targeted re-reviews at a90c49644323c2266787c0f259aa4f482bdee60b both escalated. The >=100-per-binary and genuine Windows signal rows passed, but the designated production matrix still lacks UDP-enabled, required-root-fatal, signal-grace half-close/admitted-UDP, and partial-preparation observations."
authorization = "not_required"
unblock_condition = "Explicit coordination must define a new repair ticket or approved review lifecycle before any further code change; that work must break the UDP fatal/Forced dependency, restore bounded forced-root termination, add the missing primary production lifecycle observations, and receive fresh bounded review."
+++

# M3-T04: Compose both binaries through the transactional supervisor

## Outcome

把现有 client/server composition 作为 T03 supervisor 的 production adapters，
稳定 CLI/run diagnostics，并用真实 process/listener/signal证明 transactional
startup 与 bounded shutdown。

## In scope

- CLI/exit/stable run-code mapping和one-line redacted stderr。
- Validation-before-resource order。
- Client TCP；server TCP+optional UDP；optional metrics roots的prepare/activate。
- Root fatal arbitration、OS shutdown signal、grace/force/reap。
- Reused local harness and a table-driven minimum-100-cycle process gate。

## Out of scope

- Config parser/observability/runtime internals owned by T01/T02/T03。
- 新 inbound/outbound、routing、DNS、transparent proxy、TUN、new binary 或 schema。
- Hosted/native target qualification、external interop、performance/long soak。

## Contract references

- `ADR-0023` CLI/exits/run codes和observable compatibility。
- `ADR-0024` lifecycle/ownership/failure/shutdown。
- `SPEC-0004` M3-MUST-03 and M3-MUST-08，plus composition side of MUST-06/07。
- `TEST-0004` T04 product/integration seams。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | existing CLI/config process table extended by closed run causes |
| 2 | zero-resource check table with occupied sentinel resources |
| 3 | partial preparation/activation rollback process table |
| 4 | root-fatal versus affected-flow arbitration table |
| 5 | signal/half-close/grace/force/reap table |
| 6 | existing lifecycle cycle harness with shared scenarios/owner snapshots |
| 7 | local TCP/UDP regression suites and exact ticket gates |

Runtime fake-root tests证明policy；本票只增加其无法观察的 binary/OS adapter
failure mode。

## Validation commands

```powershell
cargo test -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test cli_contract --test config_cli --test lifecycle_cycles --test local_e2e --test udp_local_e2e --locked
cargo clippy -p ferrum2-client -p ferrum2-server -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T04 implementation/integration均等待T01～T03；不得复制supervisor policy回
  binary-local helper。
- 所有 required roots先prepare；不得让 metrics/UDP/TCP background task隐藏
  fallible startup。
- 100 cycles是bounded deterministic lifecycle regression，不宣称M4 soak、
  task-count或RSS stability。
- Harness 只记录 synthetic addresses/correlation；不得输出PSK或target。

## Completion evidence

Filled by the Team Lead after integration:

- Candidate and integrated commit:
- Full/targeted review records and stable finding IDs:
- Test-budget result:
- Accepted review debt:
