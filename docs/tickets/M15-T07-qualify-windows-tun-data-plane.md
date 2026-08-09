---
id: M15-T07
milestone: M15
status: planned
depends_on:
  - M15-T06
owns:
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M15-*.md
  - docs/milestones/M15-windows-wintun-tun-data-plane.md
  - docs/review-debt.md
  - docs/roadmap.md
  - docs/tickets/M15-T07-qualify-windows-tun-data-plane.md
  - docs/workflow-debt.md
---

# M15-T07 — Qualify and close the Windows TUN data plane

## Outcome

Bind all local、hosted non-driver、privileged Windows functional、independent Windows performance/resource、
footprint and bounded review evidence to one exact accepted integration SHA，then close M15 only if every
SPEC-0016 exit criterion passes and no blocking finding or owner remains。

## Acceptance

- [ ] One exact SHA/tree/parent and clean source are recorded；all T01～T06 integrations are ancestors and
      no evidence is borrowed from another commit/run/attempt。
- [ ] Local focused、Full、Rust 1.97.1、100+ lifecycle、docs、footprint integrity and every accepted numeric
      disposition pass serially from fresh binaries。
- [ ] Automatic workflow passes quality、test-footprint、MSRV、Windows MSVC、Linux GNU、Linux musl、SIP022
      TCP/UDP、CoreDNS/BIND、required `windows-tun-e2e` and aggregate qualification；the TUN job's exact
      `profile=full functional=16/16 cycles=100/100 cleanup=PASS` marker matches candidate SHA/run/attempt。
- [ ] A separately authorized manual run passes the same-SHA Windows TUN performance/resource job and exact
      cleanup；its exact `windows-tun-performance` marker reports `witnesses=2/2 cleanup=PASS` with matching
      SHA/run/attempt，and no throughput threshold or improvement is claimed。
- [ ] Final full Architect and QA reviews examine the exact product/security/lifecycle diff and evidence，
      return no unresolved blocker/major/minor finding，and record any accepted numeric advisory rationale。
- [ ] Handoff、status、roadmap、review/workflow debt and milestone closeout distinguish product SHA from any
      docs-only descendant and record every failed run、consumed scope and prohibited remote action honestly。
- [ ] No Wintun binary、production endpoint/route、PSK、capture、build output、package or release artifact is
      committed or published；Wintun combined-distribution remains blocked pending the recorded legal decision。

## Validation

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
rustc +1.97.1 --version --verbose
cargo +1.97.1 check --workspace --all-targets --locked
cargo +1.97.1 build --workspace --bins --locked
cargo +1.97.1 test --workspace --locked
pwsh -NoProfile -File tests/platform/qualify_windows_tun.ps1 -Mode full # local diagnostic only
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

## Result

- Commit: —
- Review: —
- Notes: no remote action is authorized by the plan；record exact later authorizations and consumption here。

## Rollback / risk

Closeout is documentation-only and cannot waive a missing functional、security、privileged、performance、
cleanup or review result。Unavailable required evidence leaves the milestone validating/blocked；it is not
converted to PASS and a failed run is never silently rerun or combined with another SHA。
