---
id: M15-T07
milestone: M15
status: done
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

- [x] One exact SHA/tree/parent and clean source are recorded；all T01～T06 integrations are ancestors and
      no evidence is borrowed from another commit/run/attempt。
- [x] Local focused、Full、Rust 1.97.1、100+ lifecycle、docs、footprint integrity and every accepted numeric
      disposition pass serially from fresh binaries。
- [x] Automatic workflow passes quality、test-footprint、MSRV、Windows MSVC、Linux GNU、Linux musl、SIP022
      TCP/UDP、CoreDNS/BIND、required `windows-tun-e2e` and aggregate qualification；the TUN job's exact
      `profile=full functional=16/16 cycles=100/100 cleanup=PASS` marker matches candidate SHA/run/attempt。
- [x] A separately authorized manual run passes the same-SHA Windows TUN performance/resource job and exact
      cleanup；its exact `windows-tun-performance` marker reports `witnesses=2/2 cleanup=PASS` with matching
      SHA/run/attempt，and no throughput threshold or improvement is claimed。
- [x] Final full Architect and QA reviews examine the exact product/security/lifecycle diff and evidence，
      return no unresolved blocker/major/minor finding，and record any accepted numeric advisory rationale。
- [x] Handoff、status、roadmap、review/workflow debt and milestone closeout distinguish product SHA from any
      docs-only descendant and record every failed run、consumed scope and prohibited remote action honestly。
- [x] No Wintun binary、production endpoint/route、PSK、capture、build output、package or release artifact is
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

- Qualified product: `7ba6268ffa3c5ecc7ba2b91e3ebcae8f596ecbb9` / tree
  `72a3cfb5c881a35b1416cbf9ffea593973cc3570` / parent
  `b04432708f2229562fcb2e4d47f2bfdbfb8daec3`。All accepted T01～T06 commits are ancestors。The T07
  commit is a documentation-only descendant and does not replace this product identity。
- Review: fresh final Architect returned `PASS_WITH_NOTES` with zero blocker、major or minor finding。QA's
  initial and first targeted `PASS_WITH_NOTES` retained `QA-M15-T07-001`；two independent read-only
  diagnoses selected the canonical exact-job-name correction below and in the handoff。Second targeted QA
  returned `PASS`，closed the finding and reported blocker/major/minor `0/0/0`。T06 `+475/0/0` and milestone
  `+5303/0/0` are accepted as distinct
  case evidence with zero support/fixture growth；`queues=bounded` records configured bounds rather than
  measured internal queue depth。
- Local qualification: format、strict Clippy、workspace binary build、all-features tests、ignored 100+
  lifecycle `1/1`、docs、exact Rust 1.97.1 check/build and diff passed。The first exact Rust 1.97.1
  workspace test failed only `caller_cancellation_finishes_owned_query_before_readmission` at the cancellation
  assertion。One authorized bounded exact test passed `1/1`，then one unchanged exact workspace retry passed；
  the first result remains part of the ledger and no further rerun occurred。The local Windows controller was
  not run because T07 prohibited controller、Wintun、VM and host-network actions。
- Footprint: integrity and category sum `PASS`；code/tests `29771/50312`，ratio `1.689967 PASS`；
  case/support/fixture `44563/5152/597`，delta `+5303/0/0`。Numeric `REVIEW_REQUIRED` is accepted for
  changed test-file sizes；there is no T07 test、helper、support or fixture growth。

### Preserved T06 VM candidate chain

| Candidate | Result | Disposition |
|---|---|---|
| `c845b04ac14f948b0e927f0c9827d7cc0d6c1578` | StrictMode empty exact-process count dereference before network side effects | zero residue；array-wrapped count repaired at `739bfe7e30d683cd7c05cd07e149611a19774a01` |
| `739bfe7e30d683cd7c05cd07e149611a19774a01` | invalid quiet-window prerequisite while legitimate traffic progressed | zero residue；immediate pre-send snapshot repaired at `b04432708f2229562fcb2e4d47f2bfdbfb8daec3` |
| `b04432708f2229562fcb2e4d47f2bfdbfb8daec3` | accepted count grew but obsolete foundation-drop counter stayed zero because T05 UDP is consumed earlier | zero residue；`7ba6268…` uses positive accepted delta and retains the independent foundation-drop oracle |

Accepted VM full exit `0` in `688.7s` with
`profile=full functional=16/16 cycles=100/100 cleanup=PASS sha=7ba6268ffa3c5ecc7ba2b91e3ebcae8f596ecbb9 run_id=vm run_attempt=4`
and zero guest/host process、adapter、address、route、work or DLL residue。Accepted VM performance exit
`0` in `207.9s` with `witnesses=2/2 cleanup=PASS` and matching SHA / `run_id=vm run_attempt=5`；
RX/TX bytes `2763/27306`，packets `46/161`，all errors/discards `0`，accepted `59`，CPU `16ms`，
RSS `46018560`，handles `206`，threads `18`，UDP sessions `1`，buffered `196521`，inflight
`1`，churn `2`，grace/force `PASS`，and bounds `8388608/8/4096/4/4194304`。The PowerShell
Direct outer transport returned `1` from a stderr `ErrorRecord`；guest controller exit files were `0` and
are the authoritative result。These VM assertions are retained T06 evidence and were not independently rerun
by T07。

### Hosted ledger

| Run / attempt | SHA | Event | Failed jobs / disposition |
|---|---|---|---|
| `31301175425/1` | `24ac23a20d04593f4a0b7628d9d4cca98d050ed9` | push | `windows-tun-e2e`、quality、qualification |
| `31301650913/1` | `7e657cf345e6ab9f7c8ccbd456b1c01f6c8e55f8` | push | quality、qualification |
| `31301944351/1` | `1cfa5e916279e4b4e916d39970791b4f355d1eed` | push | quality、qualification |
| `31326649129/1` | `3fda81e23d1d9cbf85913a38293f8407d1cb4e6e` | push | quality、qualification |
| `31326656014/1` | `3fda81e23d1d9cbf85913a38293f8407d1cb4e6e` | dispatch | quality、`windows-tun-e2e`、qualification |
| `31327738183/1` | `3187a94a3939010a13547abe3d71c9d6e7b01f33` | dispatch | `windows-tun-e2e`、qualification |
| `31328482433/1` | `53fc99e552fa1785372c2fc61ce5242ee78c96c7` | dispatch | `windows-tun-e2e`、qualification |
| `31329398413/1` | `7d3589e689d3f9a6c0ed4380f4e10320f1f598c4` | dispatch | `windows-tun-e2e`、qualification |
| `31331057488/1` | `05db25c31d1c2890552c237bdf9a55d525b1b509` | dispatch | `windows-tun-e2e`、qualification |
| `31332648680/1` | `fe9ea67d7c83ae19b1c69c7dd7dce7a01b412624` | dispatch | `windows-tun-e2e`、qualification |
| `31342917322/1` | `e103c26df7dab6bb715c12c77c0c2934a549b6df` | dispatch | `windows-tun-e2e`、qualification |
| `31360024038/1` | `352999160be919520dfa8edf3624ae4c9007d08f` | push | `interop`、`windows-tun-e2e`、`platform / linux-musl`、`platform / linux-gnu`、`msrv`、`quality`、`qualification` |
| `31360038841/1` | `352999160be919520dfa8edf3624ae4c9007d08f` | dispatch | `msrv`、`platform / linux-gnu`、`interop`、`platform / linux-musl`、`quality`、`qualification`；`windows-tun-e2e` passed，then Linux-only `PACKET_QUANTUM` cfg was repaired in descendant `da38170…` |
| `31360564302/1` | `da38170947b8c708d230d14970c4a63f802accf3` | push | `windows-tun-e2e`、qualification |
| `31361033289/1` | `d4dc626de0e1b83872219575b6c3e96b9d57b9cb` | push | `windows-tun-e2e`、qualification |

Every row above is an uncredited attempt-1 failure and none was remotely rerun。The T05 descendant run
`31360570556/1` qualified T05 normally。For the accepted product，automatic push
[`31368732658/1`](https://github.com/zzffu/ferrum2/actions/runs/31368732658) and authorized full
[`31368750439/1`](https://github.com/zzffu/ferrum2/actions/runs/31368750439) had all required jobs succeed；
the latter emitted `functional=16/16 cycles=100/100 cleanup=PASS`。Independent authorized performance
[`31368752781/1`](https://github.com/zzffu/ferrum2/actions/runs/31368752781) emitted
`witnesses=2/2 cleanup=PASS`；RX/TX bytes `2763/31016`，packets `46/201`，all errors/discards `0`，
accepted `63`，CPU `16ms`，RSS `36839424`，handles `216`，threads `15`，sessions `1`，
buffered `196521`，inflight `1`，churn `2`，the same exact bounds and grace/force `PASS`。All three
accepted runs bind product SHA and attempt `1`；performance remains diagnostic only。

- Remote / artifact boundary: all authorized non-force pushes and dispatches are consumed。No hosted rerun、
  force-push、PR、tag、package、release or publication occurred in T07。No Wintun binary、real
  endpoint/route、PSK、capture、build output or evidence artifact is committed。Combined
  Wintun/Ferrum2 redistribution remains blocked pending the responsible legal decision。

## Rollback / risk

Closeout is documentation-only and cannot waive a missing functional、security、privileged、performance、
cleanup or review result。Unavailable required evidence leaves the milestone validating/blocked；it is not
converted to PASS and a failed run is never silently rerun or combined with another SHA。
