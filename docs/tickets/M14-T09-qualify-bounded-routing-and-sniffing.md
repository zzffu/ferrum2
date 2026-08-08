---
id: M14-T09
milestone: M14
status: in_progress
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

- [ ] Every T01～T08 focused command and repository Full/Rust 1.88/100+ lifecycle/doc/footprint gate
      passes serially on one exact accepted integration SHA。
- [ ] T08's full Architect/QA review and any single targeted re-review bind that SHA and leave zero
      blockers；T09 audits identity rather than repeating a full review unless the accepted product SHA
      changes。All numeric footprint findings have explicit disposition。
- [ ] After separate authorization，one non-force push passes quality、footprint、MSRV、Windows/GNU/musl、
      SIP022 TCP/UDP、CoreDNS/BIND and aggregate qualification on the exact SHA。
- [ ] Hosted routed+enabled-UDP generators use explicit schema v2 while unrelated schema-v1 fixtures
      remain unchanged；the native platform route smoke and CoreDNS/BIND client configs are locked by
      the existing qualification driver and contract test rather than a second harness。
- [ ] Failed automatic run `31282591585/1` remains visible and is never rerun；the repair is reviewed、
      locally requalified and pushed once as a new exact descendant SHA。
- [ ] After separate authorization，one manual dispatch passes the extended performance/resource job on
      that same SHA；results make no uncontracted threshold or improvement claim。
- [ ] Milestone、ticket、CI status、review/workflow debt and handoff record exact commands、exit status、
      run/attempt identity and all unrun/failed evidence without splicing。
- [ ] No force-push、unchanged-SHA rerun、PR、tag、package、release or publication occurs。

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

- Commit: —
- Review: —
- Footprint: —
- Local evidence: —
- Remote evidence: authorized；automatic run `31282591585/1` on `9a7797f714536522910dd1c7fdee8b2998c9f071`
  failed because the native routed-UDP and DNS interop generators emitted schema v1。The failed attempt
  is preserved，was not rerun，and manual performance was not dispatched。

## Rollback / risk

Qualification docs do not replace the accepted product SHA。Missing、failed、unauthorized or wrong-SHA
remote evidence blocks close rather than being summarized as pass。
