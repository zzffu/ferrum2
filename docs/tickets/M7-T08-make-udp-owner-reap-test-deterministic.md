---
id: M7-T08
milestone: M7
status: done
depends_on: [M7-T07]
owns:
  - crates/ferrum2-runtime/tests/udp_runtime.rs
---

# M7-T08 — Make the UDP owner-reap test deterministic

## Outcome

Remove the platform-dependent scheduling assumption exposed by hosted Linux in
`shared_manager_couples_session_byte_and_direct_owner_capacity`。Keep the production UDP owner、
capacity and shutdown contracts unchanged；this is one bounded test-only repair。

## Failure evidence

- Pushed exact SHA `a2b6951f0e6c398e4d7c8e7d47414f86cc24a333`，run
  [`30808225939/1`](https://github.com/zzffu/ferrum2/actions/runs/30808225939)，quality job
  `91668470588` failed at `crates/ferrum2-runtime/tests/udp_runtime.rs:613` with
  `UDP owners did not return to baseline`；the other credited groups and Budget passed。
- The exact focused test passes on Windows and passed `2000/2000` concurrent executions，but the
  same SHA fails `20/20` from the directly built Linux/WSL test executable。
- The scripted send records its observation before awaiting a zero-duration Tokio timer；the test
  then treats that observation as completion and polls cleanup only with `yield_now`。

## Acceptance

- [x] Identify the exact retained owner(s) on the Linux red path and prove the causal scheduling
      edge；do not diagnose by elapsed-time guesswork。
- [x] Make the existing send/removal/owner-slot assertions deterministic without changing product
      code、production deadlines、owner limits or shutdown behavior。
- [x] Keep the candidate to the one owned test file and preserve the exhausted M7 envelope with
      zero or negative test growth；add no dependency、retry loop or wall-clock delay widening。
- [x] The exact Linux/WSL test changes from deterministic red to at least `2000/2000` green；the
      Windows focused test、runtime test target、workspace Full、Clippy、format、Rust 1.85、Budget
      and diff checks pass。

## Validation

```powershell
cargo test -p ferrum2-runtime --test udp_runtime shared_manager_couples_session_byte_and_direct_owner_capacity --locked -- --exact --nocapture
cargo test -p ferrum2-runtime --test udp_runtime --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 9299b8dea4a19d5a9de70ac056fa483b233771b6 --candidate 56b37d885174aa628703c5623c58b5775d857e24
git diff --check 9299b8dea4a19d5a9de70ac056fa483b233771b6..56b37d885174aa628703c5623c58b5775d857e24
```

The Linux stress command must run the exact built test executable from an isolated WSL target
directory and fail on any non-zero exit。

## Result

- Commit: `56b37d885174aa628703c5623c58b5775d857e24`，parent exact
  `9299b8dea4a19d5a9de70ac056fa483b233771b6`，tree
  `3571e13339f4a779adef5002d20e42941908f1b6`；one test file `5+/6-`。
- Review: Architect and QA both `PASS_WITH_NOTES`，with no blocker、major or minor finding。
- Notes: The first Linux wait retained socket/task/7-byte owners while session/queue/scratch were
  zero。A test-only completion `Notify` replaced the scheduling-dependent 200-yield observation；
  WSL exact stress passed `2000/2000`，Windows and runtime `13/13` passed，and Full、Clippy、build、
  100+ lifecycle、docs、Rust 1.85、Budget and diff checks passed。Exact Budget is tests `25482`，
  growth `863/864`，remaining `1`，ticket growth `0`。
