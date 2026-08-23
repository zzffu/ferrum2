# ferrum2-tun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-tun` owns the private packet-loop supervisor and restartable sessions, the smoltcp stack, canonical packet parsing and fragment reassembly, bounded TCP flow bridges, and UDP candidate/association lifecycle. Routing, policy decisions, DNS behavior, and outbound transports belong to callers. Every queue and state table needs clear ownership plus packet-count, entry-count, protocol-length, timeout, and generation bounds. Do not maintain or reintroduce an aggregate TUN byte budget or startup memory formula.

The real adapter path exists only on Windows x86_64 through `ferrum2-wintun`. Other targets intentionally build a root that fails during preparation. Do not make unsupported targets appear functional. This crate forbids unsafe code; platform FFI remains isolated in `ferrum2-wintun`.

Packet admission must stay fail-closed: use one canonical IPv4/IPv6 parser, enforce declared lengths and checksums (including the IPv4 UDP zero-checksum exception), valid unicast endpoints and non-zero ports, extension-header bounds, and strict fragment reassembly limits. Reassemble accepted IPv4 and IPv6 fragments before TCP/UDP policy or checksum handling; reject overlaps and stale generations. Preserve initial-SYN-only TCP admission, flow limits, backpressure, FIN/reset behavior, and owner-thread cleanup. UDP mapping is fixed EIM by local source address, with default endpoint-independent filtering and optional address-dependent filtering. A `UdpCandidate` remains provisional until its generation-checked owner commit; never silently evict a live candidate or association, and never let an old-generation handle mutate or inject into a newer runtime.

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

Execute the compiled TUN test binary and all adapter/underlay qualification only in the pinned local
Hyper-V guest. The host may compile with `--no-run`; it must not execute TUN tests or mutate host
network state.

The reviewed static packet contract lives in `tests/fixtures/packets/reassembly-v1.hex` with exact provenance in `tests/fixtures/packets/PROVENANCE.toml`. Keep it distinct from the seed sets under `fuzz/corpus/packet_reassembly/` and `fuzz/corpus/udp_reset_races/`. The fuzz crate has empty default features. Hosted CI may format, check, and compile its deterministic and libFuzzer targets, but it must not execute them. Deterministic properties and the smoke corpus run only as prebuilt binaries inside the approved local Hyper-V guest; sanitizer-backed fuzz campaigns use the same isolated local qualification boundary.
