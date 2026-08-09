---
id: M14-T09
milestone: M14
status: done
depends_on:
  - M14-T08
owns:
  - tests/m0-harness/src/external_support/mod.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/platform/qualify_native.py
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M14-*.md
  - docs/milestones/M14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/review-debt.md
  - docs/roadmap.md
  - docs/test-plans/TEST-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/tickets/M14-T09-qualify-bounded-routing-and-sniffing.md
  - docs/workflow-debt.md
---

# M14-T09 — Qualify bounded routing and sniffing

## Outcome

Bind one accepted integration SHA，rerun all focused/local gates，obtain bounded final reviews and—only
after explicit authorization—collect automatic and independent performance/resource evidence on that
same SHA before closing M14。

## Acceptance

- [x] Every T01～T08 focused command and repository Full/Rust 1.88/100+ lifecycle/doc/footprint gate
      passes serially on one exact accepted integration SHA。
- [x] T08's full Architect/QA review and any single targeted re-review bind that SHA and leave zero
      blockers；T09 audits identity rather than repeating a full review unless the accepted product SHA
      changes。All numeric footprint findings have explicit disposition。
- [x] After separate authorization，one non-force push passes quality、footprint、MSRV、Windows/GNU/musl、
      SIP022 TCP/UDP、CoreDNS/BIND and aggregate qualification on the exact SHA。
- [x] Hosted routed+enabled-UDP generators use explicit schema v2 while unrelated schema-v1 fixtures
      remain unchanged；the native platform route smoke and CoreDNS/BIND client configs are locked by
      the existing qualification driver and contract test rather than a second harness。
- [x] Failed automatic run `31282591585/1` remains visible and is never rerun；the repair is reviewed、
      locally requalified and pushed once as a new exact descendant SHA。
- [x] After separate authorization，one manual dispatch passes the extended performance/resource job on
      that same SHA；results make no uncontracted threshold or improvement claim。
- [x] Milestone、ticket、CI status、review/workflow debt and handoff record exact commands、exit status、
      run/attempt identity and all unrun/failed evidence without splicing。
- [x] No force-push、unchanged-SHA rerun、PR、tag、package、release or publication occurs。

## Validation

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 build --workspace --bins --locked
cargo +1.88.0 test --workspace --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
cargo test -p ferrum2-m0-harness --test qualification_contract hosted_routed_udp_generators_use_schema_v2 --locked -- --exact
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

## Result

- Commit: `bc6963472d9ae8e3c84d82851fd64d78c9f2a65f`，tree
  `a5533723d251b62529daa767dd083404fa0a30bc`；the three-file repair parent is the paired docs control
  `034cef580b155fffa2407fdb085362068e9396dd`。
- Review: Architect and QA both `PASS_WITH_NOTES` on the exact product with zero blocker、major or minor
  finding。The notes only reserved hosted evidence and an uncredited local fixed-port native run；both are
  closed by the hosted runs below。
- Footprint: exact code/tests `25586/45009`，ratio `1.759126` PASS；case/support/fixture
  `39260/5152/597`，ticket delta `+43/0/0` PASS。Milestone delta `+5377/0/0` is a zero-exit
  `REVIEW_REQUIRED` advisory accepted for distinct evidence in existing harnesses；integrity PASS。
- Local evidence: every T01～T08 focused command、format、strict Clippy、workspace bins/all-features
  `413 passed / 5 ignored`、Rust 1.88 check/build/test、100+ lifecycle `1/1`、docs、qualification
  contract `19/19` and diff checks passed serially on the exact product。
- Remote evidence: failed run [`31282591585/1`](https://github.com/zzffu/ferrum2/actions/runs/31282591585)
  on `9a7797f…` remains visible and was not rerun。New-SHA automatic run
  [`31284062682/1`](https://github.com/zzffu/ferrum2/actions/runs/31284062682) passed every required
  non-performance job；manual run
  [`31284310711/1`](https://github.com/zzffu/ferrum2/actions/runs/31284310711) passed all nine jobs，with
  performance job `93170454318` reporting throughput、10k/180-sample resource、DNS resource、THP restore
  and cleanup PASS on the same SHA。

## Rollback / risk

This docs-only closeout does not replace the qualified product SHA。The schema-v1 routed+enabled-UDP
generator defect was repaired only in the existing test/tool seams；no product or workflow change was
needed。No M14 risk remains open；deferred upstream groups、fallback/retry、TUN/transparent inbounds and
management surfaces remain explicit non-goals。
