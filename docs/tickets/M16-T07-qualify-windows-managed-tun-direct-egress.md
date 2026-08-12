---
id: M16-T07
milestone: M16
status: active
depends_on:
  - M16-T06
owns:
  - .github/workflows/m0.yml
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - tests/m0-harness/src/local_support/mod.rs
  - tests/platform/qualify_windows_tun.ps1
  - docs/adr/ADR-0035-m16-client-direct-outbound.md
  - docs/adr/ADR-0036-m16-windows-managed-tun-policy.md
  - docs/handoffs/HANDOFF-M16-*.md
  - docs/history/M16-*.md
  - docs/milestones/M16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/roadmap.md
  - docs/specs/SPEC-0017-m16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/test-plans/TEST-0017-m16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/tickets/M16-T*.md
---

# M16-T07 — Qualify Windows managed TUN and direct egress

## Outcome

Freeze one exact integration SHA，run the complete local、platform、interop、current-VM IPv4 privileged and
independent performance evidence ledger，obtain bounded final Architect/QA review，and only then mark M16
closed and write the durable handoff/history。The final status commit is documentation-only and does not
replace that qualified product/control SHA or require candidate-bound evidence to be relabelled。

## Acceptance

- [ ] Candidate SHA/tree/parent and ticket ancestry are exact；no uncommitted/staged evidence，mixed candidate
      SHA or workflow/control drift exists。
- [ ] Focused and repository Full，Rust 1.97.1，Windows/GNU/musl non-driver，SIP022/DNS interop，100+ lifecycle，
      architecture and milestone footprint all pass on the same candidate；every numeric footprint finding has
      an explicit disposition。
- [ ] Fresh-restore full and hard-kill ledgers from the exact current qualification VM/checkpoint match the
      candidate；the identity-bound full marker reports `cycles=100/100`，and both unique TEST-0017 markers
      report zero owned or sentinel residue。No second Windows build or standalone cycles ledger is required
      or credited。
- [ ] The current-VM full marker retains M15 `m15_transport=16/16` including IPv6 regressions and reports only
      the M16 IPv4 additions as `direct_tcp=1/1`、`direct_udp=1/1`、`dns=2/2`、
      `network_change=3/3`、`route_change=1/1`、`interface_change=1/1` and `address_change=1/1`。The hosted full
      regression separately reports M15 `functional=16/16` and `cycles=100/100`；no preflight observation or
      hash is credited as PASS。
- [ ] After explicit remote authorization only，required push/hosted jobs and independent Windows TUN
      performance run execute against the same candidate SHA and succeed；each distinct workflow binds its own
      run ID/attempt，while each current-VM profile binds its own run token。Failed attempts remain recorded and
      are not rerun/combined as evidence。
- [ ] One fresh full Architect review and one fresh full QA review report zero blocking findings；fixes receive
      only bounded targeted re-review and cause all affected validation to rerun。
- [ ] Closure docs state IPv4 compatible routing、single-IPv4-default direct、IPv4 resolver steering、Windows
      TUN-selected direct IPv6 pre-socket refusal，preserved M15/manual-route and non-managed IPv6，and no
      strict/anti-leak/multihomed/performance-improvement claims exactly；ADR status changes only after evidence
      is complete。
- [ ] No force-push、PR、tag、package、release、publication or Wintun redistribution occurs without separate
      authorization/decision。

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
cargo +1.97.1 check --workspace --all-targets --locked
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check <accepted-M16-base>..<accepted-integration-sha>
```

The exact VM/hosted commands and run/job IDs are recorded in the ticket result and handoff after authorization；
placeholders are never reported as evidence。

Run the following in the exact restored current qualification VM before hosted evidence：

```powershell
pwsh tests/platform/qualify_windows_tun.ps1 -Mode full -IdentityLedger <exact-json> -WintunZip <exact-zip> -RunToken <unique>
pwsh tests/platform/qualify_windows_tun.ps1 -Mode hard-kill -IdentityLedger <exact-json> -WintunZip <exact-zip> -RunToken <unique>
```

Only after explicit remote authorization，use the existing workflow and a unique integration ref：

```sh
git push origin <accepted-integration-sha>:refs/heads/codex/integration/m16
gh run list --workflow m0.yml --branch codex/integration/m16 --commit <accepted-integration-sha> --json databaseId,headSha,event,attempt,status,conclusion
gh workflow run m0.yml --ref codex/integration/m16 -f dispatch_target=windows-tun-full
gh workflow run m0.yml --ref codex/integration/m16 -f dispatch_target=performance
gh run watch <automatic-or-dispatch-run-id> --exit-status
gh run view <run-id> --json attempt,conclusion,event,headSha,jobs,status,url
gh run view <full-run-id> --log
gh run view <performance-run-id> --log
```

The automatic/full ledgers require `quality`、`test-footprint`、`msrv`、`platform / windows-msvc`、
`platform / linux-gnu`、`platform / linux-musl`、`interop`、`windows-tun-e2e` and `qualification` success。
The performance dispatch additionally requires `performance` and `windows-tun-performance` success。Logs
must bind the exact SHA/run/attempt：the hosted full job contains one exact M15 transport、cycles and aggregate
full marker，while the performance job contains the existing M4 marker and one TEST-0017 M16 performance
marker。The identity-bound current-VM full/hard-kill markers remain the sole M16 capability evidence；these
hosted jobs are regression/resource gates，not a second privileged OS qualification baseline。

## Result

- Qualified commit/tree/parent: —
- Local Full/MSRV/footprint: —
- Current qualification VM/checkpoint/guest-identity evidence: —
- Hosted/performance evidence: —
- Architect/QA review: —
- Remote actions: —
- Notes: —

## Rollback / risk

Before close，rollback returns to the last accepted ticket and reruns affected evidence。After close，product
rollback uses the previous qualified M15 product/config pair；automatic config migration is not provided。
