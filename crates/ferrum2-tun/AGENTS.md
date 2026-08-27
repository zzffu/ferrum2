# ferrum2-tun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-tun` owns the private packet-loop supervisor and restartable sessions, the smoltcp stack, canonical packet parsing and fragment reassembly, bounded TCP flow bridges, and UDP candidate/association lifecycle. Routing, policy decisions, DNS behavior, and outbound transports belong to callers. Every queue and state table needs clear ownership plus packet-count, entry-count, protocol-length, timeout, and generation bounds. Do not maintain or reintroduce an aggregate TUN byte budget or startup memory formula.

The real adapter path exists only on Windows x86_64 through `ferrum2-platform-windows`. Other targets intentionally build a root that fails during preparation. Do not make unsupported targets appear functional. This crate forbids unsafe code; platform FFI remains isolated in `ferrum2-platform-windows`.

Packet admission must stay fail-closed: use one canonical IPv4/IPv6 parser, enforce declared lengths and checksums (including the IPv4 UDP zero-checksum exception), valid unicast endpoints and non-zero ports, extension-header bounds, and strict fragment reassembly limits. Reassemble accepted IPv4 and IPv6 fragments before TCP/UDP policy or checksum handling; reject overlaps and stale generations. Preserve initial-SYN-only TCP admission, flow limits, backpressure, FIN/reset behavior, and owner-thread cleanup. UDP mapping is fixed EIM by local source address, with default endpoint-independent filtering and optional address-dependent filtering. A `UdpCandidate` remains provisional until its generation-checked owner commit; never silently evict a live candidate or association, and never let an old-generation handle mutate or inject into a newer runtime.

Keep `packet.rs` focused on target-neutral parsing and validation. Local ICMP/control generation belongs
in `packet/control.rs`, while packet-only fixtures and unit cases belong in `packet/test_support.rs`
and `packet/tests.rs`. Gate these focused modules at their declaration boundary instead of scattering
the same target predicate across individual packet items.

Ordinary network-semantic changes perform a lightweight `ResetNetwork`: quiesce admission, publish
the new network generation, run reset hooks, cancel current TCP/UDP owners, clear provisional and
packet state, replace only the network runtime/stack, then reopen admission. Preserve the long-lived
adapter, Wintun session, GUID/LUID, managed addresses/routes/DNS, WFP session, and ownership ledger.
Confirmed managed-state damage or immutable TUN configuration changes use the separate full-rebuild
path with reverse cleanup. Cleanup-integrity failures remain terminal. Wintun ring-full is an
explicitly counted packet drop: do not retry it and do not reset or rebuild for it.

## Focused Verification

Run:

```text
cargo test -p ferrum2-tun --locked --no-run
```

Hosted Linux CI may additionally execute only the exact unsupported-target preparation test:

```text
cargo test -p ferrum2-tun --lib --locked process::unsupported_target_tests::unsupported_target_fails_during_preparation -- --exact --nocapture
```

Execute the compiled TUN test binary and all adapter/underlay qualification only in the pinned local
Hyper-V guest. Apart from the exact non-Windows fail-closed test above, an ordinary host may compile
with `--no-run` only; it must not execute TUN tests or mutate host network state.

The reviewed static packet contract lives in `tests/fixtures/packets/reassembly-v1.hex` with exact provenance in `tests/fixtures/packets/PROVENANCE.toml`. Keep it distinct from the seed sets under `fuzz/corpus/{packet_reassembly,udp_reset_races,config_legacy_fields,strict_route_rules}/`; the reviewed synthetic config and strict-route seeds are recorded in `fuzz/corpus/PROVENANCE.toml`. The fuzz crate has empty default features. Hosted Linux CI may format, check, compile, and run sanitizer-backed libFuzzer campaigns only against these four pure in-memory targets. The required campaign budget is one hour total, divided equally across the targets, with evolved corpora, logs, and crash artifacts retained as workflow evidence. It must never open a real TUN adapter, invoke Hyper-V, mutate host networking, or qualify the unsupported Linux adapter path. Deterministic properties and the smoke corpus continue to run only as prebuilt binaries inside the approved local Hyper-V guest.
