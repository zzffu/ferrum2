+++
id = "M1-T02"
title = "Extend the shared SIP022 TCP flow through the complete target-address path"
milestone = "M1"
status = "done"
priority = "P0"
risk = "critical"
implementation_blocked_by = ["M1-T01"]
review_blocked_by = []
integration_blocked_by = ["M1-T01"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-core/**",
  "crates/ferrum2-shadowsocks/**",
  "crates/ferrum2-socks5/**",
  "crates/ferrum2-runtime/**",
  "tests/fixtures/sip022/**",
]
spec = "docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md"
test_plan = "docs/test-plans/TEST-0002-m1-complete-tcp-methods-and-interop.md"
acceptance = [
  "All three method profiles use one opaque SIP022 TCP request, response, frame, replay, binding, detection, duplex, and terminal state path with method-derived 43/59 or 59/91 initial reads",
  "Authentication, message type, timestamp, full-width replay and response binding, tamper, truncation, nonce exhaustion, padding, length, allocation, and detection-prevention behavior passes as a three-profile matrix",
  "IPv4, IPv6, and 1-to-255-byte ASCII domain targets round-trip through normalized core, SOCKS5, SIP022, and direct-outbound representations with nonzero ports",
  "Malformed, truncated, unsupported, empty, oversized, non-ASCII, and zero-port targets cause zero resolution, dial, replay insertion, forwarding, allocation from peer size, or accepted-session mutation",
  "Domain resolution consumes at most 16 ordered candidates and resolution plus all sequential attempts share one absolute configured deadline; timeout and cancellation clean all owned work",
  "LocalEndpoint and consuming SessionReply propagate actual SocketAddr, preserve M0 IPv4 reply bytes, encode IPv6 success, and retain deterministic fixed-sequence refusal/error mapping",
  "Reusable buffers, backpressure, partial-byte accounting, half-close, task ownership, redaction, and bounded allocation retain M0 invariants without per-method state copies",
]
+++

# M1-T02: Extend the shared SIP022 TCP flow through the complete target-address path

## Outcome

把 T01 method profiles 接入唯一 SIP022 TCP state machine，并让 IPv4、IPv6、
ASCII domain target 在认证/完整校验后安全进入 bounded direct connector。

## In scope

- core normalized target 和 `SocketAddr` endpoint/reply contract。
- SOCKS5 IPv4/IPv6/domain parse/reply。
- SIP022 method-derived salt/first-read、address codecs 与 shared flow matrix。
- system-resolution boundary、16-candidate bound、single absolute connect deadline。
- address/security/order/cleanup fixtures 和 focused tests。

## Out of scope

- config/binary wiring、real-process product matrix、hosted reference qualification。
- configured listeners/SS-server endpoint family expansion。
- DNS cache/proxy/custom resolver、Happy Eyeballs、routing。
- UDP 或 public new API unrelated to the approved seam。

## Contract references

- `ADR-0018` shared method profile/state contract。
- `ADR-0019` normalized target、resolution/deadline/reply contract。
- `SPEC-0002` M1-AC-03/04/05/06。
- `TEST-0002` recording seams 与 fixture contract。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1–2 | existing Shadowsocks suites parameterized over one profile table |
| 3–4 | one core→SOCKS5→SIP022→recording connector address table |
| 5 | paused-time scripted resolver/candidates under one deadline |
| 6 | endpoint/reply family table and fixed failure sequence |
| 7 | existing buffer/duplex/lifecycle suites extended only for changed profiles |

process/hosted tests 不重复 codec rows；它们只证明后续 composition/reference
interaction。

## Validation commands

```powershell
cargo test -p ferrum2-core -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-runtime --locked
cargo clippy -p ferrum2-core -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- 该票独占 core/protocol/runtime 与 SIP022 fixtures；不得编辑 root lock、config、
  binaries 或 qualification harness。
- complete authenticated semantic header 必须先于 replay insertion/resolution/dial；
  recording sequence 是 blocking security evidence。
- partial `SocketAddrV4`→`SocketAddr` conversion 会造成 runtime success 后 reply
  failure，必须 end-to-end review。
- 16-candidate bound、single absolute deadline 与 no-Happy-Eyeballs 是 observable
  contract，不能在 helper 中静默改变。

## Completion evidence

- Branch/worktree/candidate: `codex/ticket/m1-t02`,
  `C:\project\ferrum2\.worktrees\m1-t02`,
  `ae84631c515933f60b2aa3f898a86fa3cff11ce9`; product integration commit
  `533c224964bb8b142bdc0c8dff5db8714ef9713a`.
- Reviews: Architect/QA full reviews on `2d5dfa27` blocked as
  `ARCH-M1-T02-001`/`QA-M1-T02-001`; the first bounded repair
  `6e8e3eda` received QA targeted `PASS` and Architect targeted `ESCALATE`.
  The one user-authorized additional repair `ae84631c` received Architect
  superseding `PASS` for the original finding only. Canonical root
  `M1-T02-REVIEW-001` is resolved; the full and targeted records remain in
  the runtime audit ledger.
- Authorization: single-use scopes
  `m1-t02-review-001-repair-override-20260728-a1`,
  `m1-t02-arch-001-control-amendment-ae84631-20260728-a1`, and
  `m1-t02-arch-001-review-round-override-ae84631-20260728-a1` were consumed
  and revoked at their one-use limits. They granted no ownership, contract,
  remote, destructive, push, or publish authority.
- Candidate validation: the four package tests, package Clippy, fmt,
  workspace all-target check/tests, and `git diff --check` all exited 0.
  Integration validation on `533c2249`: binary build; authoritative quick
  fmt/check/tests; and authoritative full fmt/Clippy/all-feature tests/docs
  all exited 0.
- Test budget: ticket gate `PASS`, code `7710`, tests `15511`, ratio `2.012`;
  baseline `7031/14707/2.092`; delta `+324/+415`, allowance `444`.
- Accepted review debt: none for T02. Push/publish: none.
