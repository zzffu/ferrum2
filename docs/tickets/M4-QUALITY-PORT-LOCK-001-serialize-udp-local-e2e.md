---
id: M4-QUALITY-PORT-LOCK-001
milestone: M4
status: done
depends_on: [M4-THP-PROFILE-001]
owns:
  - tests/m0-harness/tests/udp_local_e2e.rs
---

# M4-QUALITY-PORT-LOCK-001 — Serialize UDP local E2E port ownership

## Outcome

Make the existing UDP local real-process tests deterministic under the authoritative
parallel workspace test command by serializing their shared TCP/UDP port handoff
boundary. Product behavior and the shared port helper remain unchanged.

## Acceptance

- [x] One file-local standard-library mutex is held for the full lifetime of all five
      tests in `udp_local_e2e.rs`, including the ignored IPv6 case.
- [x] The pre-fix native-ext4 WSL loop reproduces the hosted `occupy UDP` / Linux
      `EADDRINUSE` failure, while the fixed default-parallel file and minimized pair
      each pass 200 consecutive runs.
- [x] No product, shared helper, dependency, workflow, test-thread setting, retry, or
      remote state changes.
- [x] Focused, Full, ticket-budget, milestone-budget, diff, and cleanliness checks pass.

## Validation

```sh
cargo test -p ferrum2-m0-harness --test udp_local_e2e --locked
cargo test -p ferrum2-m0-harness --locked
sh scripts/test-budget.sh ticket --base 35fb3f85633ee32ba5909ecbf5d74c4ad4a89f11 --candidate <candidate-sha>
```

Run the serial Full and milestone-budget commands from
`docs/agents/milestone-workflow.md`. WSL remains diagnostic; hosted acceptance still
requires a future separately authorized exact-SHA push run.

## Result

- Commit: `5f4fed7e0835298fee820ece7b858db45ea34044`
- Review: exact one-file diff `PASS`; no blocker, major, minor, or note finding.
- Notes: pre-fix default-parallel native-ext4 WSL reproduced the exact line-224
  `occupy UDP` / `EADDRINUSE` failure on iteration 4. After the file-level mutex,
  WSL default parallel and the minimized pair each passed `200/200`; the ignored IPv6
  case and complete harness passed on native ext4. Full passed `6/6`, including the
  ignored lifecycle gate in `127.62` seconds. Ticket and milestone budgets returned
  `PASS_ADVANCE` at code `14172`, tests `20873`, examples `132`, ratio `1.472834`, with
  ticket debt `7` and milestone debt `-2056`. Scope is consumed; no push, rerun,
  dispatch, PR, release, or publication occurred.
