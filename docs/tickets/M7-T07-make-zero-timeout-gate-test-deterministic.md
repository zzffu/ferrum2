---
id: M7-T07
milestone: M7
status: done
depends_on: [M7-T06]
owns:
  - tests/m0-harness/tests/qualification_contract.rs
  - docs/tickets/M7-T07-make-zero-timeout-gate-test-deterministic.md
---

# M7-T07 — Make the zero-timeout gate test deterministic

## Outcome

Replace one scheduling-dependent qualification assertion with deterministic timeout and closed-peer
rows。This is the approved bounded repair for the Full failure found after M7-T06；it changes no
production gate、timeout、interop contract or product code。

- Exact base: `92d849ecd9c21bc4a3fdaf37aa826a32470f4504`。
- Exact candidate: `ffcbccd16cbc6f643471040405cc89e04d728f0a`。

## Acceptance

- [x] The exact base reproduces the race under a 2,000-run、32-way stress loop；the candidate has
      zero failures under the same loop。
- [x] The zero-timeout row sends no acknowledgement while its sender remains alive through join，
      so it can observe only timeout rather than a queued ACK or disconnect。
- [x] Target failure、application failure、timeout and explicit closed-peer evidence remain，with no
      sleep、retry、deadline widening or production implementation change。
- [x] The diff is limited to the owned test file、`4+/4-`；rustloc remains code/tests/examples
      `15529/25483/132` and schema 2 Budget passes with zero ticket growth。
- [x] `QA-M7T07-001` is closed by targeted QA review and the accepted chain passes integration
      validation。

## Validation

```powershell
cargo test --workspace --all-features --locked --test qualification_contract tcp_exchange_accepts_hosted_sing_box_reference_client_observation_order -- --exact
cargo test --workspace --all-features --locked --test qualification_contract
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 92d849ecd9c21bc4a3fdaf37aa826a32470f4504 --candidate ffcbccd16cbc6f643471040405cc89e04d728f0a
git diff --check 92d849ecd9c21bc4a3fdaf37aa826a32470f4504..ffcbccd16cbc6f643471040405cc89e04d728f0a
```

The stress gate runs the exact built qualification test executable 2,000 times with PowerShell
`ForEach-Object -Parallel -ThrottleLimit 32` and fails if any process exits non-zero。

## Result

- Commit: candidate `ffcbccd16cbc6f643471040405cc89e04d728f0a`，parent `92d849e`。
- Review: Architect `PASS`；QA technical checks PASS but initially blocked `QA-M7T07-001` because
  this ticket and the truthful frontier were absent。Two required independent read-only xhigh
  analyses agreed that the code needed no change；control exact `cb69992e49580e9f090c940554f129348d12c302`
  added the contract，and targeted QA returned `PASS / CLOSED`。
- Notes: base stress failed `14/2000` in the primary run and `13/2000` independently；candidate
  passed `0/2000` in the engineer、primary and QA runs。On accepted integration exact `cb69992`，
  target stress remained `0/2000` and format、Clippy、build、workspace Full、100+ lifecycle、docs、
  MSRV、ticket/milestone Budget and diff checks all passed。
