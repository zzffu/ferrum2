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
- `M2-T02` `qa` `0d88666d2f46`: QA-M2-T02-N01: T04 must invoke public UdpServer::commit_request only inside T03 reserved commit_*_with closure; verify exact call placement during T04 integration review.
<!-- review-debt:10059c5c38f4 -->
- `M2-T04` `architect` `6896c6e02679`: ARCH-M2-T04-N01: IPv6 real-process target evidence remains NOT EXECUTED on this Windows host; require exact-SHA IPv6-capable platform evidence.
<!-- review-debt:4276fb90dc85 -->
- `M2-T04` `qa` `6896c6e02679`: QA-M2-T04-N01: IPv6 remains NOT EXECUTED on this Windows host and requires exact-SHA IPv6-capable platform evidence; build exact candidate binaries before process harness execution.

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
<!-- review-debt:006f5eb5f3bb -->
- `M2-T05` `qa` `c31290eb572a`: QA-M2-T05-HOSTED-N01: **RESOLVED at `0395d7dfb170`** by replacing the 10 ms wait with the bounded 100 ms test deadline.
<!-- review-debt:ab2f5bf41a1f -->
- `M2-T05` `qa` `c31290eb572a`: QA-M2-T05-HOSTED-N02: **RESOLVED at `0395d7dfb170`** by separating the application gate from the target worker owner.
<!-- review-debt:31bb37d17cb3 -->
- `M2-T05` `architect` `0395d7dfb170`: ARCH-M2-T05-HOSTED-N02: the 100 ms focused scheduler bound remains advisory after one loaded 100-run sequence timed out once and a diagnostic 100/100 repeat passed.
