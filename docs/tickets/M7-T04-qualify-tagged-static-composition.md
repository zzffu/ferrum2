---
id: M7-T04
milestone: M7
status: done
depends_on: [M7-T03]
owns:
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/platform/qualify_native.py
---

# M7-T04 — Qualify tagged static composition

## Outcome

Reuse the existing process/platform/interop harnesses to prove bounded multi-instance behavior and
qualify one exact integration SHA without a new provider、workflow job or performance claim。

## Acceptance

- [x] A bounded real-process table exercises at least two client and server inbounds/outbounds、
      both static TCP/UDP mappings、shared outbound and no-fallback；all three methods are covered
      without a tag cross product。
- [x] Focused process rows prove aggregate admission、cross-listener replay/UDP binding、partial
      bind rollback、root fatal、signal shutdown、at least 100 completed cycles and exact rebind。
- [x] Existing legacy config/CLI、local TCP、server UDP、SOCKS UDP and architecture gates remain；
      core/protocol modules contain no Endpoint/config/runtime dependency or generic registry。
- [x] Existing external TCP and UDP case IDs/methods/references/deadlines/cleanup remain unchanged
      and pass `12/12` each on the accepted SHA。
- [x] Windows MSVC、Linux GNU/musl native rows run tagged offline validation and bounded
      multi-listener rollback/rebind；missing/setup/skipped is BLOCKED。
- [x] Exact integration passes Full、Rust 1.85 and final blocking review；the test-budget outcome
      is recorded exactly。Under the explicit user waiver，`ratio_ceiling_exceeded` is
      nonblocking for T04 but is not a budget PASS。After separate explicit authorization only，
      one same-SHA run/attempt may supply hosted evidence；no result splicing、rerun、second push、
      PR、tag、release or publication。

## Validation

Run `TEST-0008` T04、integration and hosted commands exactly as recorded。

## Result

- Commit/run: exact `953689ad2c9984a317f617e26444db7aa173513a`，tree
  `01594ef4efbd8e5bd242da6a5bda671989600c10`；automatic push run
  [`30794873478/1`](https://github.com/zzffu/ferrum2/actions/runs/30794873478)。
- Review: hosted MSRV UDP cleanup repair `9e1b169` received Architect
  `PASS_WITH_NOTES` and QA `BLOCK` on `QA-M7T04-005`。The required two independent xhigh
  analyses confirmed the TCP cleanup gap and identified the complete parent-owned socket
  inheritance boundary；final exact `953689a` received Architect and QA
  `PASS_WITH_NOTES` with no blocker、major or minor finding。
- Notes: Linux Rust 1.85 default-parallel `local_e2e` passed `100/100`；Windows passed
  `8/8`；TEST-0008、workspace Full/MSRV、ignored 100+ lifecycle、Clippy、format and diff
  checks passed。Hosted MSRV、Windows、GNU、musl and interop succeeded；interop emitted TCP
  `12/12`、UDP `12/12` and both cleanup PASS on the exact SHA。Quality's authoritative Full
  step succeeded，then its budget step alone failed `ratio_ceiling_exceeded`；performance was
  not awaited or credited。The authorized non-force push was consumed；no rerun、second push、
  PR、tag、release or publication occurred。

## Rollback / risk

Evidence-only changes may revert independently before close，but they cannot waive T01～T03
product evidence or reuse M6 results as M7 qualification。Performance remains a repository
regression only，not an M7 acceptance threshold。
