---
id: M16-T06
milestone: M16
status: planned
depends_on:
  - M16-T05
owns:
  - crates/ferrum2-wintun/src/
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/tun.rs
  - tests/platform/qualify_windows_tun.ps1
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - tests/m0-harness/tests/local_e2e.rs
---

# M16-T06 — Close managed-TUN lifecycle and Windows evidence

## Outcome

Close the integrated failure/lifecycle boundary：route/interface/address invalidation revokes capture and
terminates，every setup/cleanup ordinal is mutation-tested，and fresh-restore current-VM full（including its
identity-bound 100-cycle row）and hard-kill profiles prove zero owned residue without a new harness or widened
security claim。

## Acceptance

- [ ] Route/interface/address callbacks only signal the owner，cannot use freed context or perform blocking/
      logging/policy work，and cancellation completes before callback state is released。
- [ ] Any change that invalidates frozen underlay or owned route identity rejects new sockets，removes capture
      and DNS steering，then uses existing supervised termination；established flows are not migrated and no
      fail-closed guarantee is claimed。
- [ ] Fake failure injection covers every underlay/adapter/address/session/DNS/route/notification/ack ordinal，
      the conditional interface-metric lease when selected，owner panic，external replacement conflicts and
      repeated/coalesced invalidation with exact cleanup order。
- [ ] After restoring the exact current qualification VM/checkpoint，the full profile covers direct/proxy
      IPv4/IPv6 TCP/UDP，system DNS UDP/TCP，one real route mutation、one real interface mutation and real IPv4
      plus IPv6 unicast-address mutations，graceful/forced stop and sentinels on one exact candidate。Every
      network-change row proves callback observation、new-admission rejection、capture/DNS removal、supervised
      termination and residue cleanup。
- [ ] The same qualification asset completes 100 cycles with zero OS and process-private owner counters。
      Separate external `TerminateProcess` rows prove only process absence and zero adapter/address/route/DNS
      residue before controller remediation/checkpoint restore and emit the exact TEST-0017 `cases=3/3`
      hard-kill marker bound to the identity ledger、candidate SHA、probe SHA-256 and its own unique run token。
- [ ] Existing M0～M15 Full、interop、platform and lifecycle behavior remains green；footprint numeric findings
      are dispositioned，not hidden by deleting independent evidence。
- [ ] Ticket-level Architect/QA review reports zero blocking findings。

## Validation

```powershell
cargo test -p ferrum2-wintun network_change --locked
cargo test -p ferrum2-client managed_tun_lifecycle --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
pwsh tests/platform/qualify_windows_tun.ps1 -Mode full -IdentityLedger <exact-json> -WintunZip <exact-zip> -RunToken <unique>
pwsh tests/platform/qualify_windows_tun.ps1 -Mode hard-kill -IdentityLedger <exact-json> -WintunZip <exact-zip> -RunToken <unique>
cargo test -p ferrum2-m0-harness --test architecture m16_observability --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <accepted-M16-T05-sha> --candidate <candidate-sha>
cargo fmt --all -- --check
git diff --check <accepted-M16-T05-sha>..<candidate-sha>
```

Run privileged commands only in the exact restored qualification VM；the host performs only Hyper-V control
and read-only residue audit。

## Result

- Commit: —
- Qualification VM/checkpoint/guest-identity evidence: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback returns to accepted T05 but the milestone cannot close without this ticket。The main risk is treating
normal RAII cleanup as hard-kill evidence；external process termination and OS snapshots are mandatory。
