---
id: M16-T06
milestone: M16
status: done
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

Close the integrated failure/lifecycle boundary：IPv4 route/interface/address invalidation revokes capture and
terminates，every setup/cleanup ordinal is mutation-tested，and fresh-restore current-VM full（including its
identity-bound 100-cycle row）and hard-kill profiles prove zero owned residue without a new harness or widened
security claim。

## Acceptance

- [x] IPv4 route/interface/address callbacks only signal the owner，cannot use freed context or perform blocking/
      logging/policy work，and cancellation completes before callback state is released。
- [x] Any change that invalidates frozen underlay or owned route identity rejects new sockets，removes capture
      and DNS steering，then uses existing supervised termination；established flows are not migrated and no
      fail-closed guarantee is claimed。
- [x] Fake failure injection covers every underlay/adapter/address/session/DNS/route/notification/ack ordinal，
      the conditional interface-metric lease when selected，owner panic，external replacement conflicts and
      repeated/coalesced invalidation with exact cleanup order。
- [x] After restoring the exact current qualification VM/checkpoint，the full profile preserves M15 transport
      `16/16` including its existing IPv6 rows，then covers M16 IPv4 direct TCP `1/1`、direct UDP `1/1`、system
      DNS UDP/TCP `2/2`，one real IPv4 route mutation、one real interface mutation and one real IPv4 unicast-
      address mutation for `network_change=3/3` and `address_change=1/1`，plus graceful/forced stop and sentinels
      on one exact candidate。Every
      network-change row proves callback observation、new-admission rejection、capture/DNS removal、supervised
      termination and residue cleanup。
- [x] The same qualification asset completes 100 cycles with zero OS and process-private owner counters。
      Separate external `TerminateProcess` rows prove only process absence and zero adapter/address/route/DNS
      residue before controller remediation/checkpoint restore and emit the exact TEST-0017 `cases=3/3`
      hard-kill marker bound to the identity ledger、candidate SHA、probe SHA-256 and its own unique run token。
- [x] Existing M0～M15 Full、interop、platform and lifecycle behavior remains green；footprint numeric findings
      are dispositioned，not hidden by deleting independent evidence。
- [x] The full/qualification markers retain `m15_transport=16/16` and use exactly `direct_tcp=1/1`、
      `direct_udp=1/1`、`dns=2/2`、`network_change=3/3`、`route_change=1/1`、
      `interface_change=1/1` and `address_change=1/1`；preflight hashes or observations are never PASS rows。
- [x] Ticket-level Architect/QA review reports zero blocking findings。

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

- Commit: `d76268b61c4b6ce47ba48dcf4e306e0b2917ef3a`（tree
  `15f5897d4ed05765531b2e65c550dde91f32cb30`，parent
  `553843ae01bb74297faffac64d6ddec573b4e7d7`；ticket base `54f06a4…`）。
- Qualification VM/checkpoint/guest-identity evidence: Fresh `full` run token
  `m16t06-full-20260811211853-fd65dd5d` exited `0` with one exact marker：M15 `16/16`、Direct TCP/UDP
  `1/1`、DNS `2/2`、network changes `3/3`、cycles `100/100`、hard kill `3/3` and cleanup PASS。
  Independent fresh `hard-kill` token `m16t06-hardkill-20260811213654-58010a25` exited `0` with `cases=3/3`。
  Both bind Windows 10 Enterprise Evaluation build `19044.1288`、candidate `d76268b…` and probe
  `a14553c777cec98083f50aa0688fcfbf168da348d9968035d266afbb519d58b9`；listener counts are respectively
  `3/2` and `2/1`，pre-remediation residue is zero and final restore reaches four stable baseline samples。
- Review: Final root Architect and QA audits are both `PASS` with zero blocker、major or minor。The callback /
  owner / revocation / cleanup source trace and exact VM evidence close all prior findings。
- Footprint: Integrity/category/ratio `PASS`；ticket numeric `REVIEW_REQUIRED` is accepted at code/tests
  `30395/56913`、ratio `1.872446` and case/support/fixture delta `+2287/0/0`。The large existing qualifier and
  architecture table carry distinct callback、ordinal、cycle and controller evidence；no support/fixture/new
  harness is added，so deleting it would remove independent evidence。
- Notes: Local focused Wintun/client/architecture/policy gates、workspace Full、strict Clippy、bins、Rust
  `1.97.1`、doc and ignored lifecycle all pass on the exact candidate。Earlier failed VM/controller attempts
  remain uncredited；the final two tokens above are fresh and self-contained。Performance and hosted exact-SHA
  qualification remain M16-T07 work。

## Rollback / risk

Rollback returns to accepted T05 but the milestone cannot close without this ticket。The main risk is treating
normal RAII cleanup as hard-kill evidence；external process termination and OS snapshots are mandatory。
