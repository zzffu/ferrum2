---
id: M10-T03
milestone: M10
status: done
depends_on: [M10-T02]
owns:
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M10-*.md
  - docs/milestones/M10-manual-outbound-selector.md
  - docs/roadmap.md
  - docs/tickets/M10-T03-qualify-manual-selector.md
---

# M10-T03 — Qualify manual selector

## Outcome

Reuse existing process、platform and interoperability evidence to qualify one exact M10 integration SHA，
without inventing a child-process switch channel、new provider/job or performance claim。

## Acceptance

- [x] Public-interface and four data-plane focused tests pass on the locally validated product exact SHA
      (not yet qualified)；query/switch/
      concurrency/error claims do not rely on private state or a process control backdoor。
- [x] Existing real-process tagged/routed TCP and UDP rows prove configured default startup、no-fallback、
      response binding、100+ lifecycle and exact restart/rebind without a new harness/helper。
- [x] The unchanged architecture test plus exact-product-SHA Architect inspection prove one core selector
      module、no protocol/runtime policy duplicate、no new trait/dependency/control transport and no
      tag/selection telemetry；no selector-specific architecture test growth is claimed。
- [x] Exact integration passes Full、Rust 1.85、three native targets、existing TCP/UDP `12/12` each、
      schema 3 footprint and final blocking review。
- [x] Any hosted evidence uses one exact SHA/run/attempt only after separate explicit authorization；no
      splicing、rerun、second push、PR、tag、release or publication。

## Validation

Ran the public selector command、all four exact T02 commands、`TEST-0011` T03 commands and the serial
integration gate exactly as recorded。After explicit authorization，one non-force push started automatic
run `30906020944/1` on the exact integration SHA；no rerun or second remote action was used。

## Result

- Product ancestor under qualification: `93ed9d91929200a1786694ffd59e491b7188a5d1`；local validation
  checkpoint:
  `eb56b81b709a8e18e4560fbad8cd3b3b27ced44a`。T03 adds product/test LOC `0/0` and
  case/support/fixture LOC `0/0/0`。
- Focused local evidence: public selector `2/2`；four data-plane commands `1/1` each；real-process
  TCP/UDP `1/1` each；architecture `9/9`；Rust 1.85 check passed。
- Serial Full: format、Clippy、binary build、workspace `308 passed / 5 ignored`、lifecycle `1/1`
  (`126.57s`)、docs and diff checks passed。
- Review: exact-product Architect inspection bound target
  `93ed9d91929200a1786694ffd59e491b7188a5d1`、tree
  `ded9f1e59da892250215f13a271b927579192592` and parent
  `c55c6c8e737e419b5fa036bf5572183b90f56cd0`；verdict `PASS_WITH_NOTES` with no new blocker/major/
  minor，and existing `ARCH-M10T02-001` / `M10-T02-QA-N01` remain accepted。This closes
  `M10-T03-QA-002` as local architecture evidence only，not hosted qualification or closure。
  T01 Architect `PASS_WITH_NOTES` and final QA `PASS` closed `QA-M10T01-001`；T02 Architect/
  QA both `PASS_WITH_NOTES` with no blocker/major/minor。`ARCH-M10T02-001` and
  `M10-T02-QA-N01` accept the two large `run.rs` file signals without a new helper/harness。
- Initial full T03 Architect/QA reviews blocked docs candidate `146e8d5` on `ARCH-M10T03-001` and
  `M10-T03-QA-001/002/003`。Two user-mandated independent xhigh analyses selected this five-doc
  repair。Reviewed repair `a274a7cdb71ad74af5b2b8bb36cd2f32d2b96396` received targeted
  Architect and QA `PASS`；all four findings are resolved，and current local integration descends from
  that repair。
- Footprint: ticket `PASS` with `0/0/0` case/support/fixture delta；milestone zero-exit
  `REVIEW_REQUIRED` with integrity/change `PASS`、code/tests `16646/27319`、ratio `1.641175` and
  cumulative `403/0/0`。`ARCH-M10T02-001` / `M10-T02-QA-N01` accept the large-file signals。
- Qualified integration: `2df141e720580d2f8fe16bee6c9698f4e85a520a`，tree
  `a9a7370499aa2749afab9c7b78ea9e53dd10cf27`。Automatic push run
  [`30906020944/1`](https://github.com/zzffu/ferrum2/actions/runs/30906020944) completed `success`；
  quality `91981153772`、test-footprint `91981153797`、MSRV `91981153779`、Windows MSVC
  `91981153760`、Linux GNU `91981153841`、Linux musl `91981153800`、interop
  `91981153770`、performance `91981153828` and qualification `91991168302` all succeeded。
- Same-SHA markers report Full/security/process、schema 3 footprint、Rust 1.85、three platforms、
  TCP/UDP each `12/12` plus cleanup、10,000 sessions/180 samples/RSS `6/6`/drain and aggregate
  `PASS`。No old M8 or cross-run evidence was credited。
- Final exact hosted-SHA Architect returned `PASS_WITH_NOTES` and QA `PASS` with no new finding；all
  acceptance items are met，T03 is `done` and M10 may close。Performance ran `42m51s` and remains
  regression/aggregate evidence only；M10 adds no threshold or claim。The push authorization is consumed，
  and no rerun、second push、dispatch、PR、tag、release or publication is authorized。

## Rollback / risk

The qualified SHA and run/attempt must remain immutable evidence。Performance remains regression-only；
automatic policy、external control、persistence and connection interruption require a new contract。
