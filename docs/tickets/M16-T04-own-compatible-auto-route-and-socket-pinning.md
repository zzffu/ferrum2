---
id: M16-T04
milestone: M16
status: done
depends_on:
  - M16-T03
owns:
  - crates/ferrum2-wintun/Cargo.toml
  - crates/ferrum2-wintun/src/
  - crates/ferrum2-tun/src/lib.rs
  - bins/ferrum2-client/Cargo.toml
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/egress/
  - bins/ferrum2-client/src/run/tun.rs
  - Cargo.lock
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M16-T04 — Own compatible capture routes and socket pinning

## Outcome

Add the IPv4 compatible auto-route vertical to the existing Wintun lifetime：capture-before underlay snapshot，
IPv4 endpoint/default physical policy，pre-connect/pre-send binding and an exact journaled `/1` capture
transaction，
then compose the managed TUN root last without changing `ProcessSupervisor` or synchronous activation。

## Acceptance

- [x] Existing `ferrum2-wintun` remains the sole unsafe Windows Adapter；route/binding ABI details、handles and
      callback-ready identities stay private and no new crate/package identity appears。
- [x] While auto-route is true，reachable physical first hops must resolve to IPv4。Fixed Shadowsocks endpoints
      and direct/no-detour DNS bootstraps use exact GetBestInterfaceEx→validated identity→constrained
      GetBestRoute2；an IPv6 concrete proxy or direct/no-detour DNS physical endpoint fails validation/prepare
      before mutation，while an IPv6 logical bootstrap behind an IPv4 proxy first hop remains allowed。Dynamic
      IPv4 direct uses the unique IPv4 default accepted by T01。Missing/ambiguous/changed policy fails before
      capture or rejects the flow，never unpinned。
- [x] IPv4 `IP_UNICAST_IF` uses correct network byte order and precedes TCP connect/UDP send for proxy、direct
      and DNS physical sockets；fake recorders and VM A/B prove the boundary。No IPv6 binder is published。
- [x] Windows TUN+direct publishes its read-only IPv4 default binder before Ready with auto-route off；a
      controller-added post-Ready manual capture route cannot recapture IPv4 direct。TUN-selected direct IPv6
      fails pre-socket for auto-route off/on。No-direct manual mode performs no new managed-network state
      query/mutation and preserves M15，including its IPv6 adapter/data plane。
- [x] Every capture row uses the T01-frozen values，full initializer override，absent precheck，ActiveStore exact
      readback and reverse conditional journal delete；no `/0`、physical bypass、route flush/adopt or system-row
      ownership exists。
- [x] TUN root is the final prepared/activated root；notifications precede snapshot，capture is the final host
      mutation，post-capture generation/fingerprint revalidation closes the race，activation remains admission-
      only，and every prepare ordinal or composition failure reverses owned state。
- [x] `auto_route = false` always preserves M15 host state；except for the required TUN+direct binder above，
      existing socket behavior is unchanged，including IPv6 proxy and absent/direct-detour DNS physical egress
      when no TUN-origin direct operation is selected。Non-Windows targets build with no managed-network path。
- [x] The T01 IPv4 interface-metric disposition is closed：either source/VM guards prove no mutation，or the
      selected Wintun-only IPv4 lease passes snapshot/apply/readback/partial failure/external replacement/
      conditional restore and residue rows。
- [x] Planned Wintun `m16_redaction` tests prove route/prefix、interface index/LUID/GUID/name、adapter and endpoint
      sentinels never escape fixed error/outcome categories。
- [x] Focused fake/platform tests、architecture/unsafe guards and footprint disposition pass。

## Validation

```sh
cargo test -p ferrum2-wintun managed_route --locked
cargo test -p ferrum2-wintun underlay --locked
cargo test -p ferrum2-wintun m16_redaction --locked
cargo test -p ferrum2-client managed_tun_lifecycle --locked
cargo test -p ferrum2-client direct_ --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
sh scripts/test-budget.sh ticket --base <accepted-M16-T03-sha> --candidate <candidate-sha>
git diff --check <accepted-M16-T03-sha>..<candidate-sha>
```

Privileged pinned/unpinned rows are rerun after restoring the exact current qualification VM/checkpoint before
integration；they are not replaced by the fake recorder or another guest。

## Result

- Commit: `2fdfbc7d0106e90e61739b810896f2feb17295cd`（tree
  `a4b2cc02bbd7dbc8a03a0256b266be4792d1f65d`，parent
  `2c770b7a3ef4f7896e24aea25d32b88df29cae48`）。
- Review: final Architect and QA both `PASS_WITH_NOTES`，each with zero blocker/major/minor and one accepted
  footprint-size note；T04 may close。
- Footprint: integrity `PASS`；numeric `REVIEW_REQUIRED` is accepted at code/tests `31688/54418`、ratio
  `1.717306 PASS`、case/support/fixture delta `+2094/0/0` and code growth `+1347`。The existing
  `architecture.rs` reaches `4975` semantic test LOC（`+270`）；the evidence remains in existing seams with no
  support/fixture growth or second harness。
- Evidence: the candidate-bound probe/client SHA-256 values are
  `b6d118321e19def01f5bcc6b10bacc55948025e9a88515ce4d8c7447e86ee35d` and
  `98c5454018dbdf0867972d6ccf1a4e58e7825cf18dbd1032315734bf626597c9`。On Windows 10 Enterprise
  Evaluation、`EnterpriseEval`、AMD64、version `10.0.19044.0`、build `19044.1288`，the official product
  qualifier exited `0` with one PASS marker and phases
  `before|auto-active|auto-cleanup|manual-active|after`。The listener observed TCP/UDP `4/4`；PktMon observed
  unpinned TCP/UDP `5/1` and zero packets for all six pinned rows；auto cleanup was `0/0/0/0/0`。Manual capture
  owned two routes and TCP/UDP `1/1` round-tripped；guest residue was zero，host fingerprints were unchanged，
  and final restored baseline was `1/1/1/1` with four stable samples and a pristine audit。
- Notes: interface metric remained unchanged。The official controller SHA-256 was
  `5e2b9f8d5d91c6ea00456347e5d80b7c39d14a30fae2d41854618c5f5f32d7cc`；its post-attempt
  array-tokenization-only repair `08d6396c6d792bc83fa6f59b42c079eec70118aeb9d7d7e6b721662594cc62fd`
  passed offline replay but is not credited as another VM run。Earlier controller/staging/test-only failed
  attempts remain uncredited and do not contribute to PASS；they performed no successful product qualification
  and left no residue。This result is limited to the exact guest build and makes no cross-build claim。

## Rollback / risk

Rollback disables/removes only product-managed capture/binding and returns to M15 manual route plus T03
direct behavior。The main risk is recursive self-capture；connect/send-before-bind and unpinned fallback
mutations are blocking。
