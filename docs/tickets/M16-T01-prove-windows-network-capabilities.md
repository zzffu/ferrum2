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

# M16-T01 — Prove IPv4 Windows network capabilities and freeze contracts

## Outcome

Starting from the accepted exact IPv4 scope amendment atop the single-VM M16 plan，accept one platform-probe
plus Markdown-evidence commit that proves，on the current approved Hyper-V VM/checkpoint，that the selected
IPv4 capture rows、socket binding、Wintun DNS steering、capture-before-admission interval and hard-kill cleanup
are physically viable before any product implementation begins。This ticket does not modify protected
footprint/workflow control，claim managed IPv6 or claim another Windows build。

## Acceptance

- [ ] The parent is the accepted exact Markdown-only IPv4 scope amendment descended from single-VM amendment
      `a8205c2…`；qualified M15 and planning SHA/tree/parent resolve，and inherited schema-3 verification reports
      M16 base `fcef80d…` with `29771/50323`。
- [ ] ADR-0035/0036、SPEC/TEST-0017、CONTEXT、roadmap and all tickets agree on direct singleton plans、chain
      rejection、one IPv4 default for dynamic direct、IPv4 endpoint-specific fixed binding、IPv4 `/1` capture、
      Wintun-only IPv4 DNS steering、Windows TUN direct IPv6 pre-socket refusal、no WFP and no live migration。
- [ ] The existing Windows TUN qualifier gains one bounded `network-feasibility` mode rather than a second
      controller；the host never runs the qualifier/product or mutates route、address、firewall、adapter or TUN
      state，and exact VM/checkpoint identity、actual guest OS identity and build/probe hashes are recorded。
- [ ] The host may start only one bounded TCP+UDP echo listener on a runtime-discovered eligible physical IPv4
      as the off-link support endpoint。Its exact chosen ports、PID and owner extend the existing ordered local
      identity ledger/hash；it auto-exits or is explicitly stopped and is audited absent after every attempt。
      No firewall exception is added：if existing policy does not admit it，this ticket is `BLOCKED`。The prior
      successful reachability/absence audit is preflight only，not PASS。
- [ ] Before mutation，the host records the exact TEST-0017 canonical identity ledger from Hyper-V readback and
      PowerShell Direct，hashes it，and requires the capability marker's distinct candidate、probe、identity and
      run-token fields to match；the VM display name is never accepted as guest OS evidence。
- [ ] VM `Windows 10 MSIX packaging environment` is restored from checkpoint
      `M15-T04-before-2b0c25b-20260810`；the runner records actual product、edition、architecture and full
      version/build，then proves fully initialized capture create/readback/exact delete，freezing next-hop
      derivation、route metric and interface-metric disposition。
- [ ] IPv4 fixed-first-hop and dynamic-direct tables each prove unpinned off-link TCP/UDP enters Wintun while
      pre-connect/pre-send pinned traffic reaches its owned endpoint with zero Wintun ingress；GetBest API
      order and the one IPv4 dynamic default are observable，for `tcp_pin=4/4` and `udp_pin=4/4`。
- [ ] The restored VM proves Wintun per-interface IPv4 DNS drives Windows resolver UDP and TCP to the exact
      synthetic IPv4 address without changing physical DNS or the M15 IPv6 adapter address，for `dns=2/2`，
      and proves the capture-before-admission interval
      remains bounded。
- [ ] Partial apply and normal supervised stop leave zero OS and in-process owners。External `TerminateProcess`
      separately proves process absence plus zero adapter/address/route/DNS residue before controller cleanup；
      it does not claim process-private drain counters。
- [ ] Any failed/missing row leaves this ticket BLOCKED，records the evidence and stops T02；no product knob、
      service/watchdog、WFP or unit-fake waiver is added。
- [ ] The existing qualifier and its route/socket/resolver/cleanup tables/helpers are the cheapest sufficient
      layer；no second harness or third equivalent helper is added。The preflight rationale is never recorded
      as PASS or expanded with raw local IDs、addresses、ports、credentials、PIDs or owner identifiers；no
      listener helper or endpoint is committed。
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
evidence；never run the qualifier/product on the host or substitute another VM without a plan amendment。The
only host process allowed is the ledger-bound transient listener above，and its absence audit is mandatory。

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
