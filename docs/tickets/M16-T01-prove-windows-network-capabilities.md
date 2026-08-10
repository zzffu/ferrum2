---
id: M16-T01
milestone: M16
status: done
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

- [x] The parent is the accepted exact Markdown-only IPv4 scope amendment descended from single-VM amendment
      `a8205c2…`；qualified M15 and planning SHA/tree/parent resolve，and inherited schema-3 verification reports
      M16 base `fcef80d…` with `29771/50323`。
- [x] ADR-0035/0036、SPEC/TEST-0017、CONTEXT、roadmap and all tickets agree on direct singleton plans、chain
      rejection、one IPv4 default for dynamic direct、IPv4 endpoint-specific fixed binding、IPv4 `/1` capture、
      Wintun-only IPv4 DNS steering、Windows TUN direct IPv6 pre-socket refusal、no WFP and no live migration。
- [x] The existing Windows TUN qualifier gains one bounded `network-feasibility` mode rather than a second
      controller；the host never runs the qualifier/product or mutates route、address、firewall、adapter or TUN
      state，and exact VM/checkpoint identity、actual guest OS identity and build/probe hashes are recorded。
- [x] The host may start only one bounded TCP+UDP echo listener on a runtime-discovered eligible physical IPv4
      as the off-link support endpoint。Its exact chosen ports、PID and owner extend the existing ordered local
      identity ledger/hash；it auto-exits or is explicitly stopped and is audited absent after every attempt。
      No firewall exception is added：if existing policy does not admit it，this ticket is `BLOCKED`。The prior
      successful reachability/absence audit is preflight only，not PASS。
- [x] Before mutation，the host records the exact TEST-0017 canonical identity ledger from Hyper-V readback and
      PowerShell Direct，hashes it，and requires the capability marker's distinct candidate、probe、identity and
      run-token fields to match；the VM display name is never accepted as guest OS evidence。
- [x] VM `Windows 10 MSIX packaging environment` is restored from checkpoint
      `M15-T04-before-2b0c25b-20260810`；the runner records actual product、edition、architecture and full
      version/build，then proves fully initialized capture create/readback/exact delete，freezing next-hop
      derivation、route metric and interface-metric disposition。
- [x] IPv4 fixed-first-hop and dynamic-direct tables each prove unpinned off-link TCP/UDP enters Wintun while
      pre-connect/pre-send pinned traffic reaches its owned endpoint with zero Wintun ingress；GetBest API
      order and the one IPv4 dynamic default are observable，for `tcp_pin=4/4` and `udp_pin=4/4`。
- [x] The restored VM proves Wintun per-interface IPv4 DNS drives Windows resolver UDP and TCP to the exact
      synthetic IPv4 address without changing physical DNS or the M15 IPv6 adapter address，for `dns=2/2`，
      and proves the capture-before-admission interval
      remains bounded。
- [x] Partial apply and normal supervised stop leave zero OS and in-process owners。External `TerminateProcess`
      separately proves process absence plus zero adapter/address/route/DNS residue before controller cleanup；
      it does not claim process-private drain counters。
- [x] Any failed/missing row leaves this ticket BLOCKED，records the evidence and stops T02；no product knob、
      service/watchdog、WFP or unit-fake waiver is added。
- [x] The existing qualifier and its route/socket/resolver/cleanup tables/helpers are the cheapest sufficient
      layer；no second harness or third equivalent helper is added。The preflight rationale is never recorded
      as PASS or expanded with raw local IDs、addresses、ports、credentials、PIDs or owner identifiers；no
      listener helper or endpoint is committed。
- [x] Only a complete PASS may change ADR-0035/0036 to Accepted and SPEC/TEST-0017 to Approved，record the
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

- Bound base: `451edcbe04bc4abe7950f64dd10c1c25c7a692b0`，tree
  `a1fca1aa2ec122212d789275ceb1bf22f6839b35`，parent
  `9ec96c5eac62e44a42342dee164b4d23750617bf`。
- Probe candidate: `cc26aba03d816dfd29e8e04177a6f70a9d009b37`，tree
  `b12a3027e5f46fece89787940581134316f7214f`，parent
  `fdfc8901d5d87aa01765ec55557272bab6d6441d`；probe SHA-256
  `58b18f2d33da8f065f8f572acf252b64d6a503ecc61e59b1cd45843796f5ca90`。The Markdown evidence
  amendment is the normal single-parent descendant that closes this ticket。
- Qualification identity: exact named VM/checkpoint restored；guest Windows 10 Enterprise Evaluation、
  `EnterpriseEval`、AMD64、version `10.0.19044.0`、build `19044.1288`；one IPv4 default and zero IPv6
  defaults。Canonical identity-ledger SHA-256 is
  `f3a5393fb85bbaf25c898c2dc15ee2e99734a9041aa99909cd5d2dd777907502`；raw ledger values remain local。
- Frozen route/binding contract: exact `0.0.0.0/1` + `128.0.0.0/1` capture rows，next hop `0.0.0.0`，row
  metric `1`，interface metric `unchanged` with no lease。Fixed binding is
  `GetBestInterfaceEx(destination)` → validate physical index → interface-constrained `GetBestRoute2` →
  freeze preferred source/route fingerprint；dynamic binding is the one unique pre-capture IPv4 default。
  Both measured underlay rows had prefix length `0`、row metric `0` and the same physical interface/source/
  next hop，without recording those identities。
- Marker:

  ```text
  m16_windows_network_feasibility status=PASS routes=2/2 tcp_pin=4/4 udp_pin=4/4 dns=2/2 capture_window=1/1 hard_kill=1/1 interface_metric=unchanged cleanup=PASS guest_build=19044.1288 run_token=m16t01-20260810210826-e9356cac candidate_sha=cc26aba03d816dfd29e8e04177a6f70a9d009b37 probe_sha256=58b18f2d33da8f065f8f572acf252b64d6a503ecc61e59b1cd45843796f5ca90 identity_sha256=f3a5393fb85bbaf25c898c2dc15ee2e99734a9041aa99909cd5d2dd777907502
  ```

- Evidence: qualifier exit `0`，stdout exactly the one marker above，stderr empty；phases exactly
  `before|active|normal-cleanup|hard-kill-active|after`。Capture window was `768 ms`。PktMon filtered
  unpinned/pinned deltas were fixed TCP `5/0`、dynamic TCP `5/0`、fixed UDP `1/0`、dynamic UDP `1/0`；the
  bounded listener completed TCP/UDP `3/3` with no fault and was absent afterward。Guest pre-remediation
  product/adapter/address/route/DNS/work/PktMon residue was zero/absent，host network/firewall fingerprints
  matched before/after/final，and the final checkpoint restore was pristine with no cleanup-error/failure file。
- Validation: PowerShell AST parse PASS；schema-3 `test-budget verify` baseline PASS at code/tests
  `29771/50323`、ratio `1.690336`、case/support/fixture `44574/5152/597`；workspace policy `25/25`、
  architecture `19/19`、`cargo fmt --all -- --check` and `git diff --check` all exit `0`。The normal commit
  hook and exact post-commit ticket-footprint readback bind the evidence amendment itself。
- Review: independent Architect/QA review pending；the acceptance review checkbox remains open。
- Notes: T01 is done and T02 is ready because every capability row passed。This is single-asset IPv4 evidence，
  not managed IPv6 or cross-build qualification；no raw local endpoint、interface、process or credential value
  is repository evidence。

## Rollback / risk

Rollback removes only T01 probe/evidence amendments and leaves the accepted M16 planning/control commit
intact。The accepted limitation is that one-build evidence proves only the exact current qualification asset；
the blocking risks inside that boundary remain fake evidence、wrong restored identity and missing
pinned/unpinned controls。
