+++
id = "M2-T05"
title = "Add the twelve-case fail-closed hosted UDP qualification"
milestone = "M2"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M2-T02"]
review_blocked_by = []
integration_blocked_by = ["M2-T01", "M2-T02", "M2-T03", "M2-T04"]
release_blocked_by = ["M2-T04"]
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-shadowsocks/examples/udp_protocol_client.rs",
  "tests/m0-harness/Cargo.toml",
  "tests/m0-harness/src/bin/m0_qualification.rs",
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/src/qualification/**",
  "tests/m0-harness/tests/qualification_contract.rs",
  "tests/interop/**",
  ".github/workflows/**",
]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "M2-UDP-INT-001 through M2-UDP-INT-012 cover each supported method, pinned reference, and direction tuple exactly once in the approved method-major order with no discovery, skipped, waived, or duplicate row",
  "Ferrum-client rows spawn the Cargo-managed Shadowsocks UDP protocol example as a black-box process and reference-client rows target the composed ferrum2 server, while the qualification harness adds no ferrum library dependency and no public client UDP inbound",
  "Every case reuses one session for three distinct request and reply datagrams, validates payload and observed source address, and owns independent temp paths, ports, child processes, absolute deadlines, bounded redacted capture, sockets, and cleanup",
  "Pinned sing-box 1.13.14 and shadowsocks-rust 1.24.0 provenance, asset size and SHA-256, safe extraction, version output, license and UDP configuration are verified before their rows execute",
  "Reference setup failure marks its six rows failed under one canonical root while the other reference remains runnable; panic, timeout, missing, skipped, mismatch, nonzero or cleanup failure cannot produce a success result",
  "Local quick and full only compile and lint the example and Cargo-managed qualification entry and run the pure aggregation contract; they never execute qualification, download references, open external sockets, or spawn reference processes",
  "After separate authorization, exit zero requires one clean GitHub Actions Linux checkout at exact GITHUB_SHA and an explicit twelve-line 12-of-12 plus cleanup report on one run and attempt; missing or unavailable evidence remains BLOCKED",
]

[blocker]
id = "M2-T05-QUALIFICATION-001"
class = "test_evidence"
gate = "release"
root_cause = "The locally repaired and reviewed candidate has not run hosted Linux qualification at the eventual final integration SHA; run 30408245840 covers only superseded SHA a168b89 and failed three TCP rows."
derivatives = []
owner = "team_lead"
evidence = "Product repair 0395d7dfb170ddc8c3328b2d939210d96c81266f passed bounded Architect/QA verification and preliminary local product/control integration is 6a4e35062bd6d1631a029230e7cffdc3ba0f7db6. No new push, hosted run, or external qualification is authorized or executed."
authorization = "required"
unblock_condition = "After separate exact-SHA remote authorization, one clean hosted run/attempt must pass quality, MSRV, Windows, Linux GNU/musl, provider setup, TCP 12/12 plus cleanup, and UDP 12/12 plus cleanup; missing or failed evidence remains blocking."
+++

# M2-T05: Add the twelve-case fail-closed hosted UDP qualification

## Outcome

扩展既有thin hosted qualification为固定12项UDP compatibility gate，同时以
black-box Cargo example使用public protocol API，保持harness independence。

## In scope

- `M2-UDP-INT-001..012` fixed plan和three-datagram/source checks。
- Protocol example process adapter；reference UDP configs/provisioning。
- Canonical setup roots、failure continuation、exact-SHA/summary/cleanup guards。
- Existing quality/MSRV/platform/interop hosted profile的最小扩展。

## Out of scope

- Product crypto/protocol/runtime/server fixes。
- Public client inbound、SOCKS5 UDP ASSOCIATE或new CI job matrix。
- 本票自动push/run/rerun/publish；remote action另需授权。

## Contract references

- `docs/research/M2-udp-baseline.md`：pins和case order。
- `SPEC-0003` M2-AC-07/08。
- `TEST-0003` hosted table、false-PASS和local/external boundary。
- ADR-0006/0017的provenance、exact-SHA和thin CI rules。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | pure fixed case-plan uniqueness table |
| 2 | Cargo metadata/dependency inspection + process launch contract |
| 3 | per-case result/cleanup contract |
| 4 | existing pinned provisioning checks extended for UDP |
| 5 | pure aggregation failure-continuation table |
| 6 | local build/lint/pure commands and no-execution guard |
| 7 | one authorized raw hosted 12/12+cleanup report |

Hosted compatibility不能替代ferrum-ownedcrypto/state/resource evidence。

## Validation commands

```powershell
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo metadata --no-deps --format-version 1 --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

不得在local执行`m0-qualification`。

## Ownership and risks

- T05 example是唯一允许链接ferrum protocol crate的client adapter；
  `ferrum2-m0-harness` manifest不得增加任何ferrum dependency。
- T05可在T02后implement/review，但只有T04 integrated后才可integration/release。
- Provider/setup unavailable是release blocker，不修改product票或拼接旧run。
- 既有binary名称可保留；不为命名cleanup制造额外测试。

## Completion evidence

- Branch/worktree/candidates: `codex/ticket/m2-t05`,
  `C:\project\ferrum2\.worktrees\m2-t05`; initial
  `6c321ebbed07e426e66b8257792920595cfc0dd2`, first repair
  `975276a90b6ae4b5a9bd984bcc31e3709d473ed5`, and user-authorized
  superseding repair
  `bc589ee53e3fbf093bfe876e40a962e9f43444c2`. Cherry-picked integration
  commits are `0801a39095fd1c088698c3a2bf75062fc0bc8061`,
  `0f3c8ae8d42df9d4333ed9bc04570a5e28531a44`, and exact reviewed
  assembly `90c173f014f84761ee485ec584b7aa3fe8e7abab`.
- Reviews: QA full `BLOCK` on `QA-M2-T05-001`; Architect full `BLOCK` on
  `ARCH-M2-T05-001` and `ARCH-M2-T05-002`. The first repair resolved
  cleanup ownership but targeted Architect/QA both `ESCALATE` on the
  remaining ADR-0014 ordering IDs and repair-introduced budget IDs. After
  explicit user authorization, `bc589ee` restored forward equality then
  reverse equality before application write shutdown and legitimately
  consolidated the test delta. Architect and QA superseding reviews both
  returned `PASS`; full and targeted history is preserved and canonical
  root `M2-T05-REVIEW-001` is resolved.
- Control amendment: user-authorized
  `dff012a4a7ec88b0d5492b2efe9bea76c4510f30` permits an authorized
  superseding review to resolve blocking IDs frozen in the targeted
  escalation, including `introduced_by_repair`, without permitting new
  findings or weakening root/SHA/repair/single-use authorization controls.
  Its focused tests passed `3/3`, the full workflow suite passed `67/67`,
  and exact-SHA Architect/QA control reviews both returned `PASS`.
- Local integration evidence on `90c173f`: workspace binaries, protocol
  example and Cargo-managed qualification entry built; the pure
  qualification contract passed `12/12`; authoritative quick passed `3/3`
  and full passed `4/4`, including strict Clippy, all-features tests, the
  fixed 100-cycle lifecycle row, and docs. Metadata, workflow validation,
  review/integration gates, and diff/status checks passed. Architect
  integration review returned `PASS`; QA returned `PASS_WITH_NOTES` with
  nonblocking `M2-INT-QA-001`.
- Test budget: superseding candidate total `code=10760`,
  `tests=18197`, ratio `1.691`; ticket delta `132/250`, allowance `252`;
  repair delta `0/0`, allowance `120`. Exact integration ticket gate
  passed at `code=11714`, `tests=18971`, ratio `1.620`, delta
  `1086/1024`, allowance `1206`; milestone gate passed at
  `3994/3212`, allowance `4114`.
- Release evidence: the external qualification entry was never invoked
  locally. No hosted run/attempt, reference provisioning, IPv6 platform
  qualification, push, or publication is credited. Those remain a
  separately authorized release gate.

## Hosted failure repair evidence

- Hosted run `30408245840`, attempt `1`, passed setup and every quality/platform
  job. All twelve UDP rows and the other TCP rows passed, while SingBox
  reference-client rows `M1-INT-003`, `M1-INT-007`, and `M1-INT-011` failed for
  canonical root/finding `M2-T05-HOSTED-001` with
  `TCP exchange event is out of order: ApplicationCleanEof`.
- Before the two-way repair, the focused command
  `cargo test -p ferrum2-m0-harness --test qualification_contract --locked
  tcp_exchange_accepts_hosted_sing_box_reference_client_observation_order --
  --exact` failed `1/1` with
  `target owner completed before application acknowledgement`.
- After the repair, `cargo test -p ferrum2-m0-harness --test
  qualification_contract --locked tcp_exchange -- --nocapture` passed `2/2`,
  retaining strict raw event-order rejection while proving the bounded
  target-shutdown/application-acknowledgement handshake for all three affected
  rows.
- Superseding compaction provenance is parent
  `c31290eb572aedc236be3613d23136fae17406ff`, repair base
  `a168b89eb8dcd0c7a06df06b95a57d63893f2ab6`, and original ticket base
  `6946c9ae0099d617b21ba5575d254cf366d50122`. The local repair-base gate passes
  at code/tests `0/120` with allowance `120`; the original-base gate passes at
  `1086/1144` with allowance `1206`. The full qualification contract passed
  `13/13`. Exact-SHA `0395d7df` QA verification returned `PASS`; Architect
  returned `PASS_WITH_NOTES` after one loaded 100-run sequence timed out once
  and a diagnostic repeat passed `100/100`. Both blocking IDs are resolved;
  the 100 ms focused scheduler bound remains nonblocking debt.
- Append-only hosted review control is integrated from `f95b821f` plus repair
  `6bc85d65`. Its initial Architect `BLOCK` IDs `ARCH-M2-T04-001/002` were
  resolved by the sole targeted repair; focused root-cycle tests passed `5/5`,
  the full workflow suite passed `73/73`, and exact repair Architect/QA gates
  both returned `PASS`.
- Runtime history closes `M2-T05-HOSTED-001` and its local causal/budget
  derivatives without claiming hosted success. The remaining exact-final-SHA
  evidence gap is canonical release root `M2-T05-QUALIFICATION-001`.
  Qualification rerun, push, publication, and reference-provider operations
  remain separately authorized release actions.
