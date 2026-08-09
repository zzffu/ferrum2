# Review Debt

Non-blocking findings accepted for integration. Each item must identify the ticket,
reviewer, candidate commit, impact, and a concrete follow-up trigger. Do not promote
an advisory to a blocker after the first full review unless a repair introduced the
problem or the user explicitly reopens the contract.

## ARCH-M1-N01 — OS resolver cancellation evidence wording

- **Milestone/tickets:** M1；M1-T02、M1-T03
- **Reviewer/verdict:** Architect `PASS_WITH_NOTES`
- **Reviewed candidate:** `4cccde449ee57b91001aee4d152207bc4b3fbfc4`
- **Impact:** M1 仍要求 deadline/cancellation 后丢弃并终止等待 ferrum-owned
  resolver future、candidate sockets 和 flow-owned work；测试、日志、review 或
  completion report 不得把这个可观察结果夸大为可移植地强制取消已进入 OS 的
  resolver syscall。
- **Follow-up trigger:** M1-T02 的 resolver/dialer implementation、ticket review
  与 M1-T03 real-process evidence 明确使用 owner/future/socket seam 的措辞；
  若实现需要强制 OS-level cancellation，则必须先提交新的 platform/concurrency
  contract，而不能把它视为本 note 已批准。
<!-- review-debt:8c6ba083f74e -->
- `M1-T01` `qa` `4223051eeae3`: QA-M1-T01-001: Initial workspace-test setup failed because required process binaries were absent; the unchanged candidate passed after the normal workspace binary build. Keep clean CI/integration setup ordering explicit.
<!-- review-debt:c0092c86422e -->
- `M1-T03` `architect` `4c9ad421e0ef`: ARCH-M1-T03-001: Real-process IPv6 target row was NOT EXECUTED on this Windows host because raw [::1] connect fails WSAEACCES; IPv4 fallback proves only third-method echo/half-close. Require an IPv6-capable exact-SHA release/platform run; do not credit local IPv6 PASS.
<!-- review-debt:b7fa23a5a2c8 -->
- `M1-T03` `qa` `4c9ad421e0ef`: QA-M1-T03-001: Record real-process IPv6 as NOT EXECUTED on Windows WSAEACCES and require exact-SHA IPv6-capable release/platform evidence; fallback is not IPv6 PASS.
<!-- review-debt:706cf6f25501 -->
- `M1-T03` `qa` `4c9ad421e0ef`: QA-M1-T03-002: Local platform smoke artifact run was setup-blocked by occupied fixed port 1080; run the frozen same-SHA three-platform jobs during release qualification.
<!-- review-debt:02701aae13c2 -->
- `M2-T02` `qa` `0d88666d2f46`: QA-M2-T02-N01: **RESOLVED by T04 and retained at `7907cda05a5`**; public request and response protocol commits execute only inside the T03 reserved `commit_*_with` closures.
<!-- review-debt:10059c5c38f4 -->
- `M2-T04` `architect` `6896c6e02679`: ARCH-M2-T04-N01: **RESOLVED at `7907cda05a5` / run `30425476328` attempt 1**; the Windows T04 row remains historically NOT EXECUTED, while the exact-SHA Linux quality job executed the focused IPv4-ingress-to-IPv6-direct-target row once with payload/source/cleanup PASS.
<!-- review-debt:4276fb90dc85 -->
- `M2-T04` `qa` `6896c6e02679`: QA-M2-T04-N01: **RESOLVED at `7907cda05a5` / run `30425476328` attempt 1**; exact candidate binaries and the qualification example were built before the focused Linux process row, which passed once with `1 passed / 0 ignored` and an exact SHA/run/attempt completion marker.

## M2-INT-QA-001 — Parallel server-test readiness contention

- **Milestone/tickets:** M2；M2-T04、M2-T05 integration
- **Reviewer/verdict:** QA `PASS_WITH_NOTES`
- **Reviewed candidate:** `90c173f014f84761ee485ec584b7aa3fe8e7abab`
- **Impact:** 一次default-parallel `cargo test -p ferrum2-server --locked`
  在三个listener readiness assertions超时；同一candidate的bounded
  single-thread UDP rerun `3/3`、fully-qualified lifecycle witness `1/1`和
  Team Lead authoritative full gate均通过。因此当前证据只表明local
  test-fixture port/readiness contention风险，不表明shipped server defect。
- **Follow-up trigger:** 仅当authoritative quick/full或hosted exact-SHA gate
  再现同类失败，或有证据指向product listener ownership/lifecycle缺陷时，
  才建立新的diagnosis/repair root；不得仅凭本次advisory重开T04/T05。
- **2026-07-29 follow-up:** 两个full gate并发运行时，`6fd07a0`上的
  lifecycle registry witness再次超时；移除并发后，同一用例单次及`20/20`
  均通过，后续serialized full也通过，因此没有product lifecycle defect
  证据。另一次serialized full暴露的是独立fixture缺陷：TCP动态端口可能落入
  Windows UDP exclusion range。`M2-T04-PORT-001`以`87c3c32`的bounded
  paired reservation修复并在`3fae42a`通过full `4/4`。本advisory继续保留，
  并收窄为不得并发运行resource-heavy full gates；若serialized gate再次出现
  readiness failure，再建立新的root。
<!-- review-debt:006f5eb5f3bb -->
- `M2-T05` `qa` `c31290eb572a`: QA-M2-T05-HOSTED-N01: **RESOLVED at `0395d7dfb170`** by replacing the 10 ms wait with the bounded 100 ms test deadline.
<!-- review-debt:ab2f5bf41a1f -->
- `M2-T05` `qa` `c31290eb572a`: QA-M2-T05-HOSTED-N02: **RESOLVED at `0395d7dfb170`** by separating the application gate from the target worker owner.
<!-- review-debt:31bb37d17cb3 -->
- `M2-T05` `architect` `0395d7dfb170`: ARCH-M2-T05-HOSTED-N02: the 100 ms focused scheduler bound remains advisory after one loaded 100-run sequence timed out once and a diagnostic 100/100 repeat passed.

## M3 close review notes

### ARCH-M3-CLOSE-N01 — T06 imported-commit SHA transcription

- **Milestone/ticket:** M3；M3-T06 close evidence。
- **Reviewer/verdict:** Architect `PASS_WITH_NOTES`。
- **Reviewed sources:** local closeout source
  `d784b06171723bb93fd467cea1a799f58f7d60b0`；qualified product
  `d9e59d787c3fe78dfca778ee8a36668a45387368`。
- **Impact:** completion evidence wrote nonexistent `263ceddf...`; the correct
  imported T04 repair is `263cedda699f7f2e2ef1516438c5025296e862ca`。
  Product lineage, stable patch-id and architecture were unaffected。
- **Resolution:** mechanically corrected during M3 closeout；no ticket repair,
  review round, product validation or remote action required。

Product Manager also returned `PASS_WITH_NOTES`: all eight exit criteria passed，
while closeout still had to refresh AGENTS context、audit、vision、gap analysis、
roadmap、CI status、handoff and the accepted budget baseline。Those mechanical
close actions are resolved by the closeout commit。ADR-0023's elapsed
compatibility window and proposed M4 performance/resource qualification remain
future contract obligations, not open M3 blockers。

## M5 close review notes

### QA-T03-N01 — Anonymous raw-log download limitation

- **Milestone/ticket:** M5；M5-T03。
- **Reviewer/verdict:** QA `PASS`。
- **Reviewed candidate/run:** `6ca043460f0a5233a0b39c9931b4f3f3a22f1cba`；
  `30743888837/1`。
- **Impact:** anonymous GitHub raw-log download returned HTTP 403/rate-limit
  responses. Public run/job metadata, the logged-in job pages, exact completion
  markers and the fail-closed final job consistently proved every required gate;
  no M5 evidence is missing or spliced.
- **Follow-up trigger:** only if a future qualification cannot be audited through
  public metadata and visible job evidence, add a separately authorized read-only log
  retrieval capability. Do not reopen M5 for this access limitation alone.

## M7 close audit

No M7 review debt remains。M7-T08 Architect and QA both returned `PASS_WITH_NOTES` with no
blocker、major or minor finding；the exact candidate and hosted descendant passed the contracted
local、review、platform、interop and schema 2 Budget gates。Performance exclusion is an explicit
scope boundary, not review debt。

## M8 close audit

No M8 review debt remains。The resolver-order repair preserved the domain route contract and passed
Windows/WSL repeats plus same-SHA hosted quality and MSRV。Final Architect returned
`PASS_WITH_NOTES` and terminal QA returned `PASS` with zero blocker、major or minor finding。
Performance regression without an M8 threshold or claim is an explicit scope boundary, not debt。

## M9 close audit

No M9 review debt remains。Architect and QA both returned `PASS`。The terminology finding
`ARCH-M9-MU-001` is resolved in `CONTEXT.md`/`AGENTS.md`；QA's exact-filter finding
`M9-QA-001` is resolved by recording and running the full `run::tests::...` names，and
`M9-QA-002` is resolved by the tracked M9 contract/test map。Upstream-group deferral is an
explicit scope boundary, not review debt。

## M10 close audit

No M10 review debt remains。Final exact hosted-SHA Architect returned `PASS_WITH_NOTES` and QA
returned `PASS` with no new blocker、major、minor or note。`ARCH-M10T03-001` and
`M10-T03-QA-001/002/003` are resolved。`ARCH-M10T02-001` and `M10-T02-QA-N01` remain accepted
numeric footprint dispositions：the two existing binary test modules hold distinct real-I/O snapshot
seams，and extracting them would duplicate private composition plumbing without adding a product seam。
External control、automatic policy and the diagnostic-only performance ratio are explicit scope
boundaries，not review debt。

## M12 close audit

No M12 review debt remains。`M12-T06-ARCH-001` and `M12-T06-QA-001` were resolved by extending the
existing performance seam with DNS resource evidence；the hosted detoured-DNS owner failure then exposed
and drove the exact-plan UDP association reuse repair at
`c06386e9344c07d86ea4a3b63dc73f37f20ceb0e`。Post-repair architecture and QA audits found no blocking
issue，and automatic/manual exact-SHA qualification passed。The schema 3 numeric
`REVIEW_REQUIRED` result is accepted: case/support/fixture growth `6211/1081/0` is distinct DNS
transport、negative、lifecycle、interop and resource evidence；no fixture、second harness、copied DNS
codec or second SIP022 data plane was added。Deferred DNS features and the diagnostic-only throughput
ratio are scope boundaries，not review debt。

## M13 close audit

No M13 review debt remains。T05's copied-plan/stale-pool findings and T06's facade、test-placement and
scanner findings were resolved before qualification；the required two independent escalation analyses
converged on the final one-file architecture-guard repair。Final full Architect and QA both returned
`PASS` with zero blocker、major or minor finding。The schema 3 `changed_test_file_size`
`REVIEW_REQUIRED` signal is accepted as monolith-to-owner source reclassification：product test names
remain `92/92`，assertions are unchanged and support/fixture deltas are zero。The throughput ratio is
diagnostic only；deferred upstream groups、retry/fallback、new DNS features、TUN/transparent inbounds and
management surfaces remain scope boundaries rather than review debt。

## M14 close audit

No M14 review debt remains。All T02～T08 blocking findings were closed before qualification；where the
single-repair bound remained blocked，the required paired independent analyses converged on the accepted
existing-seam repair。T09 final Architect and QA both returned `PASS_WITH_NOTES` with zero blocker、major
or minor finding。The hosted-generator failure from `31282591585/1` is preserved and repaired on exact
`bc6963472d9ae8e3c84d82851fd64d78c9f2a65f`，which passed automatic and manual same-SHA evidence。
The schema-3 `+5377/0/0` numeric `REVIEW_REQUIRED` result is accepted as distinct parser、security、
real-process、lifecycle and mutation evidence in existing harnesses；support/fixture growth is zero。
Diagnostic throughput ratio and deferred fallback、groups、TUN/transparent and management features are
scope boundaries，not review debt。
