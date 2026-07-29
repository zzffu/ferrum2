+++
id = "M3-T06"
title = "Resolve terminal-root and forced-reap escalation"
milestone = "M3"
status = "ready"
priority = "P0"
risk = "critical"
implementation_blocked_by = ["M3-T01", "M3-T02", "M3-T03"]
review_blocked_by = []
integration_blocked_by = ["M3-T01", "M3-T02", "M3-T03"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = ["bins/ferrum2-client/src/main.rs", "bins/ferrum2-client/src/run.rs", "bins/ferrum2-server/src/main.rs", "bins/ferrum2-server/src/run.rs", "crates/ferrum2-runtime/src/process.rs", "crates/ferrum2-runtime/src/supervisor.rs", "crates/ferrum2-runtime/src/udp.rs", "crates/ferrum2-runtime/tests/shutdown.rs", "crates/ferrum2-runtime/tests/udp_runtime.rs", "tests/m0-harness/src/local_support/mod.rs", "tests/m0-harness/tests/cli_contract.rs", "tests/m0-harness/tests/lifecycle_cycles.rs", "tests/m0-harness/tests/udp_local_e2e.rs"]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "Both binaries preserve the complete M3 composition contract: CLI and exit classes, one redacted diagnostic, validation before resources, transactional TCP, optional UDP and optional metrics preparation, and normal signal exit.",
  "Proxy, UDP or metrics preparation and activation failure rolls back every acquired resource before service polling, while flow or session failures remain isolated and required-root terminal outcomes retain one deterministic process cause.",
  "A terminal required UDP-root error with live work stops admission and immediately force-cancels, joins and reaps its owned runtime without awaiting ProcessCancellation::Forced, then returns the original stable fatal cause.",
  "External shutdown uses one configured absolute drain grace; after Forced, one fixed internal five-second watchdog bounds cooperative root reaping, and any watchdog-triggered abort and join is an explicit cleanup failure mapped to shutdown.cleanup without overwriting the primary cause.",
  "Production-used direct composition evidence proves required-root fatal propagation, deterministic arbitration, cancellation, watchdog fallback and owner baseline; black-box evidence proves OS signal, TCP half-close, admitted UDP, partial preparation rollback, exit, restart and exact rebind without a product fault-injection surface.",
  "A bounded matrix records at least 100 completed real-process cycles per binary path, covering UDP enabled and disabled, rollback, graceful and forced signal paths, TCP half-close, admitted UDP, termination, child baseline and immediate rebind without claiming M4 soak.",
  "The exact candidate passes focused runtime and binary suites, CLI, config, local TCP and UDP process suites, strict Clippy, formatting, control-plane, ticket test-budget and diff gates, fresh Architect and QA review, and authoritative post-integration full gates without changes outside ownership."
]
+++

# M3-T06: Resolve terminal-root and forced-reap escalation

## Outcome

完成被 M3-T04 升级阻断的 transactional binary-composition outcome：终止态 UDP
root 不再等待由自身返回才能触发的 process `Forced`，而 process-level forced
shutdown 对不合作 root 具有固定、显式失败的终止边界。保留既有 operator、
schema、wire、CLI、logging 和 metrics contract。

## Context

- M3-T04 initial candidate
  `b35e809eda2c306be7ced27f648d2ad83ceb158c` 与唯一 repair
  `a90c49644323c2266787c0f259aa4f482bdee60b` 均未集成。
- Architect/QA targeted re-review 在 `a90c496...` 后仍以
  `ARC-M3-T04-001/002`、`QA-M3-T04-001` 升级；canonical root 为
  `ARC-M3-T04-004`。
- 用户确认 solution A 并以 `AUTH-M3-T06-001` 授权一次本地 replacement
  ticket。授权不包含 remote、T05、push、hosted qualification、publication
  或 control-plane mutation。
- T06 从 M3-T01～T03 已集成的 product base 导入上述 T04 product lineage，
  但获得独立的 full/targeted review lifecycle；T04 不得开始第三轮 review。

## In scope

- 保留 T04 的 complete client/server composition outcome、closed error mapping、
  validation-before-resource、transactional preparation、rollback 与 signal path。
- Terminal UDP `Err` 停止 admission，立即 force-cancel、join、reap 并核对其
  `DirectUdpRuntime` owners，然后才返回 original stable fatal error；该路径不得
  等待 process cancellation 进入 `Forced`。
- Operator shutdown 保持 phase-aware：一个 configured absolute drain grace，
  然后 `Forced`；`Forced` 后仅有一个固定 absolute five-second cleanup
  watchdog，不能重置或成为第二个 application grace。
- Watchdog expiry 后按 deterministic root order abort 并 await 全部 remaining
  roots；watchdog intervention 本身就是 explicit cleanup failure，即使 abort/join
  随后成功。Primary process cause 保持不变，binary outcome 为
  `shutdown.cleanup`。
- 在 production-used direct composition seam 证明 root-fatal、phase、first
  cause、join/reap 和 owner baseline；在 black-box real-process seam 证明 OS
  signal、TCP half-close、admitted UDP、rollback、exit、restart/rebind。
- 复用现有 runtime tables、binary-private scripted composition、
  `lifecycle_cycles` 和 `udp_local_e2e`；不新建 lifecycle harness。

## Out of scope

- ADR、SPEC、wire、schema v1、CLI/config、metrics identity 或 public API 扩展。
- 为测试增加 product fault-injection CLI、config 或 management surface。
- Routing、DNS、multi-inbound/outbound、transparent proxy、TUN、public UDP
  inbound、SIP023/multi-user 或 hot reload。
- M3-T05 CI/platform artifact work、remote push/run/rerun、publication、installer
  或 release。
- Performance、RSS/task stability、10,000 idle sessions 与 long soak。
- `.agents/**`、`.codex/**`、`workflow.toml` 或其他 control-plane changes。

## Contract references

- `ADR-0016` outcome-first equivalent evidence and direct-versus-black-box seam。
- `ADR-0023` preserved operator/CLI/error compatibility。
- `ADR-0024` transactional lifecycle、first cause、ownership、grace/force/reap。
- `SPEC-0004` M3-MUST-03/06/07/08。
- `TEST-0004` T06 product and integration evidence mapping。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | existing client/server and CLI/config composition tables |
| 2 | existing transactional preparation/rollback and affected-flow tables |
| 3 | production-used server scripted UDP-root-fatal composition regression with live admitted work |
| 4 | paused-time process shutdown table covering cooperative reap and exact five-second unresponsive-root cleanup failure |
| 5 | direct composition owner snapshots plus black-box lifecycle/UDP process tables |
| 6 | existing bounded lifecycle matrix with at least 100 completed cycles per binary |
| 7 | exact-SHA ticket gates, full Architect/QA reviews, integration gate and authoritative full validation |

## Implementation notes and constraints

- Preserve `PreparedProcessRoot::{activate, run, rollback}` and the watch-based
  monotonic cancellation interface。
- Zero configured grace may advance directly to final `Forced`; tests must not require
  each root to observe a distinct intermediate `Quiescing` notification。
- Create the cleanup watchdog once after broadcasting `Forced`; never reset it after
  an individual root completes。At an exact root-event/deadline race, accept a ready
  root completion before declaring timeout while retaining insertion-order root
  arbitration。
- Use an explicit closed cleanup-failure outcome for watchdog expiry; do not report
  it as `RootJoinFailed` or ordinary forced success。
- The terminal UDP path records existing forced-session accounting only for sessions
  actually force-terminated；do not add metric families or labels。
- Expected new behavior is concentrated in server UDP composition,
  `ferrum2-runtime::process`, and UDP runtime cleanup。Other owned paths carry the
  imported T04 composition/evidence lineage and should change only when compilation
  or the accepted evidence matrix requires it。

## Validation commands

```powershell
cargo test -p ferrum2-runtime --test shutdown --test udp_runtime --locked
cargo test -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test cli_contract --test config_cli --test lifecycle_cycles --test local_e2e --test udp_local_e2e --locked
cargo clippy -p ferrum2-runtime -p ferrum2-client -p ferrum2-server -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py control-plane-check --base <ticket-base-sha> --candidate-sha <candidate-sha> --json
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check <ticket-base-sha>..<candidate-sha>
```

## Ownership and risks

- T06 不依赖 M3-T04；它继承其 product delta 和 outcome，但不继承已耗尽的
  review/repair cycle。
- Watchdog fallback若被计为 ordinary forced success，会掩盖 root 未能证明
  transitive cleanup；这是 blocking correctness defect。
- Black-box process 无法可靠制造 internal root failure 或检查 owner registry；
  ADR-0016 direct composition seam 是这些 claim 的 primary evidence，不得以
  product injection surface 替代。
- Partial preparation evidence必须覆盖 proxy/TCP、UDP 和 metrics positions；
  不构造 method×platform×failure 全 cross product。
- 所有 synthetic configuration/diagnostics 不得输出 PSK、target 或 secret。

## Blocker record

Use the Git-common-dir runtime ledger for transient blockers. If a durable contract
blocker must be documented here, include ID, class, gate, root cause, derivatives,
owner, evidence, authorization state, and unblock condition.

Tracked status is durable: use only `draft`, `ready`, `blocked`, `done`, or
`deferred`. Record implementation/review/repair/integration/release with
`workflow.py set-phase`, not by editing this frontmatter.

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Required reviewer role/profile and verdict:
- Exact candidate SHA:
- Integrated commit:
