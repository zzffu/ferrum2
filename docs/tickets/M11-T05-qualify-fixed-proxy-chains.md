---
id: M11-T05
milestone: M11
status: done
depends_on: [M11-T04]
owns:
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M11-*.md
  - docs/milestones/M11-fixed-client-proxy-chains.md
  - docs/roadmap.md
  - docs/tickets/M11-T05-qualify-fixed-proxy-chains.md
---

# M11-T05 — Qualify fixed proxy chains

## Outcome

Qualify one exact M11 integration SHA with focused mixed-credential chain evidence、all repository gates、
existing platform/interop results and the separately authorized manual performance/resource job。

## Acceptance

- [x] T01 public config/plan、four T02/T03 focused composition rows and both T04 real-process rows pass on
      the accepted exact SHA with no private mutation or duplicated encoder/harness。
- [x] Serial Full、Rust 1.85、100+ lifecycle、three native targets and existing TCP/UDP `12/12` each plus
      cleanup pass without SHA/run/attempt splicing。
- [x] Schema 3 integrity passes；numeric footprint signals are explicitly accepted、reduced or reforecast
      without deleting independent evidence。Blocking Architect/QA findings are zero。
- [x] Only after explicit authorization，one non-force push runs automatic qualification and a separately
      authorized exact-SHA `workflow_dispatch` runs `performance`；both required result sets pass。
- [x] No rerun、second push、PR、tag、package、release or publication is inferred。

## Validation

Ran `TEST-0012` T05 focused reruns and the serial integration gate on exact product
`6d975c1e45eb0e614c54961e35fdc19fa2478d98`。The authorized one non-force push started automatic
qualification；the separately authorized manual dispatch produced the required independent performance
PASS on the same exact product。No rerun or second remote mutation was performed。

## Result

- Commit: product `6d975c1e45eb0e614c54961e35fdc19fa2478d98`，tree
  `2d022daccf06c31b0e7106bb1427559c9999c79b`；pre-close local docs checkpoint
  `01e498e9e9ed0179caec1d79afec0ba73dd10c17`。Remote `codex/integration/m11` points to the product
  SHA，not the docs-only descendant。
- Local evidence: public selector `3/3`、config `14/14`、CLI `5/5`；four T02/T03 composition rows
  `1/1` each；T04 TCP/UDP real-process rows `1/1` each；architecture `9/9` and Rust 1.85 all-target
  passed。Serial format、strict Clippy、workspace binaries/all-features tests、docs、diff and footprint
  gates exited `0`；the ignored 100+ lifecycle row passed `1/1` in `131.07s`。
- Footprint/review: schema 3 integrity/change passed；numeric milestone result remains the accepted
  `REVIEW_REQUIRED` signal at ratio `2.025588`、case/support/fixture growth `4993/121/0`、five file
  `WARN` and one existing client `run.rs` `REVIEW_REQUIRED`。Final closure Architect and QA both
  returned `PASS_WITH_NOTES`；no blocker or major finding remains。
- Automatic hosted evidence: immutable attempt-specific run
  [`30943770483/1`](https://github.com/zzffu/ferrum2/actions/runs/30943770483/attempts/1) completed
  `success` on the exact product SHA。Quality `92108479368`、test-footprint `92108479394`、MSRV
  `92108479373`、Windows MSVC `92108479405`、Linux GNU `92108479413`、Linux musl
  `92108479435`、interop `92108479334` and qualification `92109254228` all succeeded；performance
  `92108480457` was correctly skipped for the push event。Exact markers report TCP/UDP each `12/12`
  plus cleanup、platforms `3/3` and aggregate `PASS` for SHA/run/attempt
  `6d975c1e45eb0e614c54961e35fdc19fa2478d98/30943770483/1`。
- Manual performance evidence: workflow-dispatch run
  [`30945447936/1`](https://github.com/zzffu/ferrum2/actions/runs/30945447936/attempts/1) completed
  overall `failure`，but its independent exact-SHA performance job `92114171793` succeeded in `42m50s`
  and is the only credited result from that run。Its exact markers were：
  - `m4_throughput_completion status=PASS ferrum_median=136531148 reference_median=499539421 ratio=0.273314061 trials=10 sha=6d975c1e45eb0e614c54961e35fdc19fa2478d98 run_id=30945447936 run_attempt=1`
  - `m4_thp_profile status=APPLIED max_ptes_none=0`
  - `m4_resource_completion status=PASS sessions=10000 samples=180 rss_windows=6/6 drain=PASS sha=6d975c1e45eb0e614c54961e35fdc19fa2478d98 run_id=30945447936 run_attempt=1`
  - `m4_thp_profile status=RESTORED readback=PASS`
  - `m4_performance_completion status=PASS ferrum_median=136531148 reference_median=499539421 ratio=0.273314061 signed_difference_percent=-72.668593857 sessions=10000 samples=180 rss_windows=6/6 drain=PASS sha=6d975c1e45eb0e614c54961e35fdc19fa2478d98 run_id=30945447936 run_attempt=1`
  Post-job cleanup and `Complete job` also succeeded。The ratio is regression evidence only；M11 makes no
  throughput threshold or performance claim。
- Uncredited manual side results: duplicate MSRV `92114171828` failed at the real-process child-running
  assertion；interop `92114171762` failed `M1-INT-011` with TCP `11/12`、a poisoned trace lock and
  cleanup `FAIL`；qualification `92114925410` consequently failed。They remain failures and are not
  represented as PASS。Automatic qualification is credited only from `30943770483/1`；manual
  performance/resource evidence is credited only from `92114171793` in `30945447936/1`。This is the
  contract-defined independent evidence split，not SHA/run/attempt splicing。
- Notes: both the one push authorization and the one manual-dispatch authorization are consumed。The
  provider-created automatic attempt 2 remains uncredited。No rerun、second push/dispatch、PR、tag、
  package、release or publication was performed or is authorized。T05 is `done` and M11 is `closed`；
  the docs-only descendant is not separately hosted-qualified。

## Rollback / risk

Exact SHA/run/attempt evidence is immutable。`M11-T05-CLOSE-QA-001` retains the duplicate manual MSRV/
interop failures as residual harness-flake debt；they are neither hidden PASS results nor milestone
blockers because the complete automatic non-performance set already passed and performance is an
independent job outside qualification。Any future rerun or repair requires new authorization and a new
exact-evidence disposition。
