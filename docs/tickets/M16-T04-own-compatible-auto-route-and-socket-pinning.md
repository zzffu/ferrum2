---
id: M16-T04
milestone: M16
status: planned
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

Add the compatible auto-route vertical to the existing Wintun lifetime：capture-before underlay snapshot，
endpoint/default physical policy，pre-connect/pre-send binding and an exact journaled `/1` capture transaction，
then compose the managed TUN root last without changing `ProcessSupervisor` or synchronous activation。

## Acceptance

- [ ] Existing `ferrum2-wintun` remains the sole unsafe Windows Adapter；route/binding ABI details、handles and
      callback-ready identities stay private and no new crate/package identity appears。
- [ ] Fixed Shadowsocks endpoints and direct/no-detour DNS bootstraps use exact GetBestInterfaceEx→validated
      identity→constrained GetBestRoute2；proxy-detoured DNS pins only its selected concrete Shadowsocks first
      hop。Dynamic direct uses the unique per-family default accepted by T01。Missing/ambiguous/changed policy
      fails before capture or rejects the flow，never unpinned。
- [ ] IPv4/IPv6 socket options use correct byte order and precede TCP connect/UDP send for proxy、direct and
      DNS physical sockets；fake recorders and VM A/B prove the boundary。
- [ ] Windows TUN+direct publishes its read-only default binder before Ready with auto-route off；a controller-
      added post-Ready manual capture route cannot recapture direct。No-direct manual mode performs no new
      network query/mutation and preserves M15。
- [ ] Every capture row uses the T01-frozen values，full initializer override，absent precheck，ActiveStore exact
      readback and reverse conditional journal delete；no `/0`、physical bypass、route flush/adopt or system-row
      ownership exists。
- [ ] TUN root is the final prepared/activated root；notifications precede snapshot，capture is the final host
      mutation，post-capture generation/fingerprint revalidation closes the race，activation remains admission-
      only，and every prepare ordinal or composition failure reverses owned state。
- [ ] `auto_route = false` always preserves M15 host state；except for the required TUN+direct binder above，
      existing socket behavior is unchanged。Non-Windows targets build with no managed-network execution path。
- [ ] The T01 interface-metric disposition is closed：either source/VM guards prove no mutation，or the selected
      Wintun-only per-family lease passes snapshot/apply/readback/partial failure/external replacement/
      conditional restore and residue rows。
- [ ] Planned Wintun `m16_redaction` tests prove route/prefix、interface index/LUID/GUID/name、adapter and endpoint
      sentinels never escape fixed error/outcome categories。
- [ ] Focused fake/platform tests、architecture/unsafe guards and footprint disposition pass。

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

Privileged pinned/unpinned rows are rerun in the accepted Windows guests before integration；they are not
replaced by the fake recorder。

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback disables/removes only product-managed capture/binding and returns to M15 manual route plus T03
direct behavior。The main risk is recursive self-capture；connect/send-before-bind and unpinned fallback
mutations are blocking。
