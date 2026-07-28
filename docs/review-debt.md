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
