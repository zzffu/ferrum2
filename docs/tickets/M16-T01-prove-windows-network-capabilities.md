---
id: M16-T01
milestone: M16
status: ready
depends_on: []
owns:
  - docs/adr/ADR-0035-m16-client-direct-outbound.md
  - docs/adr/ADR-0036-m16-windows-managed-tun-policy.md
  - docs/milestones/M16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/research/M16-windows-auto-route-dns-direct-reference.md
  - docs/roadmap.md
  - docs/specs/SPEC-0017-m16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/test-plans/TEST-0017-m16-windows-managed-tun-routing-dns-direct-egress.md
  - docs/tickets/M16-T*.md
  - tests/platform/qualify_windows_tun.ps1
---

# M16-T01 — Prove Windows network capabilities and freeze contracts

## Outcome

Starting from the accepted exact single-VM scope amendment atop the M16 planning/control commit，accept one
platform-probe plus Markdown-evidence commit that proves，on the current approved Hyper-V VM/checkpoint，that
the selected capture rows、socket binding、Wintun DNS steering、capture-before-admission interval and hard-kill
cleanup are physically viable before any product implementation begins。This ticket does not modify protected
footprint/workflow control or claim another Windows build。

## Acceptance

- [ ] The parent is the accepted exact Markdown-only scope amendment descended from planning/control
      `a9619ef…`；qualified M15 and planning SHA/tree/parent resolve，and inherited schema-3 verification reports
      M16 base `fcef80d…` with `29771/50323`。
- [ ] ADR-0035/0036、SPEC/TEST-0017、CONTEXT、roadmap and all tickets agree on direct singleton plans、chain
      rejection、single-default-per-family dynamic direct、endpoint-specific fixed binding、compatible `/1`
      capture、Wintun-only DNS steering、no WFP and no live migration。
- [ ] The existing Windows TUN qualifier gains one bounded `network-feasibility` mode rather than a second
      controller；host execution is forbidden and exact VM/checkpoint identity、actual guest OS identity and
      build/probe hashes are recorded。
- [ ] Before mutation，the host records the exact TEST-0017 canonical identity ledger from Hyper-V readback and
      PowerShell Direct，hashes it，and requires the capability marker's distinct candidate、probe、identity and
      run-token fields to match；the VM display name is never accepted as guest OS evidence。
- [ ] VM `Windows 10 MSIX packaging environment` is restored from checkpoint
      `M15-T04-before-2b0c25b-20260810`；the runner records actual product、edition、architecture and full
      version/build，then proves fully initialized capture create/readback/exact delete，freezing next-hop
      derivation、route metric and interface-metric disposition。
- [ ] Both families prove unpinned off-link TCP/UDP enters Wintun while pre-connect/pre-send pinned traffic
      reaches its owned endpoint with zero Wintun ingress；fixed-endpoint GetBest API order and dynamic default
      selection are observable。
- [ ] The restored VM proves Wintun per-interface DNS drives Windows resolver UDP and TCP to the exact
      synthetic addresses without changing physical DNS，and proves the capture-before-admission interval
      remains bounded。
- [ ] Partial apply and normal supervised stop leave zero OS and in-process owners。External `TerminateProcess`
      separately proves process absence plus zero adapter/address/route/DNS residue before controller cleanup；
      it does not claim process-private drain counters。
- [ ] Any failed/missing row leaves this ticket BLOCKED，records the evidence and stops T02；no product knob、
      service/watchdog、WFP or unit-fake waiver is added。
- [ ] Only a complete PASS may change ADR-0035/0036 to Accepted and SPEC/TEST-0017 to Approved，record the
      measured route/metric formulas and make T02 ready；otherwise their proposed/draft state remains。
- [ ] Focused control/architecture validation and independent Architect/QA review pass with zero blocker。

## Validation

```powershell
git rev-parse HEAD 'HEAD^{tree}' 'HEAD^'
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
pwsh tests/platform/qualify_windows_tun.ps1 -Mode network-feasibility -IdentityLedger <exact-json> -WintunZip <exact-zip> -RunToken <unique>
cargo fmt --all -- --check
git diff --check
```

Run the feasibility command inside the exact restored qualification VM and preserve exact before/active/after
evidence；never run it on the host TUN environment or substitute another VM without a plan amendment。

## Result

- Commit: —
- Qualification VM/checkpoint/guest-identity evidence: —
- Review: —
- Notes: —

## Rollback / risk

Rollback removes only T01 probe/evidence amendments and leaves the accepted M16 planning/control commit
intact。The accepted limitation is that one-build evidence proves only the exact current qualification asset；
the blocking risks inside that boundary remain fake evidence、wrong restored identity and missing
pinned/unpinned controls。
