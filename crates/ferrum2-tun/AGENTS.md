# ferrum2-tun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-tun` owns the private packet-loop supervisor and restartable sessions, the smoltcp stack, canonical packet parsing and fragment reassembly, bounded TCP flow bridges, and UDP candidate/association lifecycle. Routing, policy decisions, DNS behavior, and outbound transports belong to callers. Every queue and state table needs clear ownership plus packet-count, entry-count, protocol-length, timeout, and generation bounds. Do not maintain or reintroduce an aggregate TUN byte budget or startup memory formula.

The real adapter path exists only on Windows x86_64 through `ferrum2-wintun`. Other targets intentionally build a root that fails during preparation. Do not make unsupported targets appear functional. This crate forbids unsafe code; platform FFI remains isolated in `ferrum2-wintun`.

Packet admission must stay fail-closed: use one canonical IPv4/IPv6 parser, enforce declared lengths and checksums (including the IPv4 UDP zero-checksum exception), valid unicast endpoints and non-zero ports, extension-header bounds, and strict fragment reassembly limits. Reassemble accepted IPv4 and IPv6 fragments before TCP/UDP policy or checksum handling; reject overlaps and stale generations. Preserve initial-SYN-only TCP admission, flow limits, backpressure, FIN/reset behavior, and owner-thread cleanup. UDP mapping is fixed EIM by local source address, with default address-dependent filtering and optional endpoint-independent filtering. A `UdpCandidate` remains provisional until its generation-checked owner commit; never silently evict a live candidate or association, and never let an old-session handle mutate or inject into a newer session.

Network-semantic changes rebuild the TUN session inside the same process. Quiesce admission first, invalidate the underlay generation, cancel session handlers, reset TCP flows, close UDP associations, clear reassembly/output state, and then clean up platform state in reverse order. Cleanup-integrity failures remain terminal. Wintun ring-full is an explicitly counted packet drop: do not retry it and do not restart the session for it.

## Focused Verification

Run:

```text
cargo test -p ferrum2-tun --locked
```

Cross-platform unit tests exercise packet and lifecycle logic under `cfg(test)`. Changes to adapter ownership or underlay binding also require Windows x86_64 platform-workflow evidence.

The reviewed static packet contract lives in `tests/fixtures/packets/reassembly-v1.hex` with exact provenance in `tests/fixtures/packets/PROVENANCE.toml`. Keep it distinct from the four seed files under `fuzz/corpus/packet_reassembly/`. The fuzz crate has empty default features: ordinary and Windows runs use only deterministic tests/smoke, while the real `packet_reassembly` libFuzzer target is compile-time rejected on Windows and enabled explicitly only by the Linux `libfuzzer-smoke` job. Parser or reassembly changes must preserve both corpora and the `deterministic-properties` plus bounded `libfuzzer-smoke` jobs in `.github/workflows/tun-fuzz-deterministic.yml`; wiring the fuzz job is not evidence that CI has executed it.
