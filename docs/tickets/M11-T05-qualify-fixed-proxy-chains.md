---
id: M11-T05
milestone: M11
status: blocked
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
- [ ] Only after explicit authorization，one non-force push runs automatic qualification and a separately
      authorized exact-SHA `workflow_dispatch` runs `performance`；both required result sets pass。
- [ ] No rerun、second push、PR、tag、package、release or publication is inferred。

## Validation

Ran `TEST-0012` T05 focused reruns and the serial integration gate on exact product
`6d975c1e45eb0e614c54961e35fdc19fa2478d98`。The authorized one non-force push started automatic
qualification；the separately authorized manual performance dispatch remains unrun。

## Result

- Commit: product `6d975c1e45eb0e614c54961e35fdc19fa2478d98`，tree
  `2d022daccf06c31b0e7106bb1427559c9999c79b`；local docs checkpoint before this record
  `b2e658aecb20c6f58158bcd86ca548e1ad5371d3`。Remote `codex/integration/m11` points to the product
  SHA，not the docs-only descendant。
- Local evidence: public selector `3/3`、config `14/14`、CLI `5/5`；four T02/T03 composition rows
  `1/1` each；T04 TCP/UDP real-process rows `1/1` each；architecture `9/9` and Rust 1.85 all-target
  passed。Serial format、strict Clippy、workspace binaries/all-features tests、docs、diff and footprint
  gates exited `0`；the ignored 100+ lifecycle row passed `1/1` in `131.07s`。
- Footprint/review: schema 3 integrity/change passed；numeric milestone result remains the accepted
  `REVIEW_REQUIRED` signal at ratio `2.025588`、case/support/fixture growth `4993/121/0`、five file
  `WARN` and one existing client `run.rs` `REVIEW_REQUIRED`。Final local and hosted Architect
  `PASS_WITH_NOTES` / QA `PASS` leave no blocker、major or minor finding。
- Automatic hosted evidence: immutable attempt-specific run
  [`30943770483/1`](https://github.com/zzffu/ferrum2/actions/runs/30943770483/attempts/1) completed
  `success` on the exact product SHA。Quality `92108479368`、test-footprint `92108479394`、MSRV
  `92108479373`、Windows MSVC `92108479405`、Linux GNU `92108479413`、Linux musl
  `92108479435`、interop `92108479334` and qualification `92109254228` all succeeded；performance
  `92108480457` was correctly skipped for the push event。Exact markers report TCP/UDP each `12/12`
  plus cleanup、platforms `3/3` and aggregate `PASS` for SHA/run/attempt
  `6d975c1e45eb0e614c54961e35fdc19fa2478d98/30943770483/1`。
- Notes: the one push authorization is consumed。The provider later created attempt 2 without a primary
  rerun request or authorization；it is not credited and does not replace immutable attempt 1。Manual
  exact-SHA performance remains separately unauthorized/unrun，so T05 is `blocked` and M11 remains
  `validating`。No second push、PR、tag、package、release or publication is authorized。

## Rollback / risk

Exact SHA/run/attempt evidence is immutable。Provider unavailable、manual performance not authorized/run、
or any skipped gate leaves M11 validating/blocked rather than converting old M10 evidence into PASS。
