# ferrum2-tun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-tun` owns the private packet-loop process root, its smoltcp stack, bounded TCP flow bridges, and UDP candidate/mapping lifecycle. Routing, policy decisions, DNS behavior, and outbound transports belong to callers. Keep configuration validation exact, including the aggregate `owned_buffer_bytes` calculation; new buffers or queues require explicit accounting and bounds.

The real adapter path exists only on Windows x86_64 through `ferrum2-wintun`. Other targets intentionally build a root that fails during preparation. Do not make unsupported targets appear functional. This crate forbids unsafe code; platform FFI remains isolated in `ferrum2-wintun`.

Packet admission must stay fail-closed: enforce MTU and declared lengths, IPv4 header and transport checksums (including the IPv4 UDP zero-checksum exception), valid unicast endpoints and non-zero ports, direct TCP/UDP headers, and rejection of IPv4 fragmentation. Preserve initial-SYN-only TCP admission, flow limits, backpressure, FIN/reset behavior, and owner-thread cleanup. For UDP, a `UdpCandidate` is provisional until its generation-checked owner commit. Respect mapping count, byte budget, payload bound, queue capacity, idle expiry, exact response source, quiesce, and stale-generation rejection; never silently evict a live/provisional entry.

## Focused Verification

Run:

```text
cargo test -p ferrum2-tun --locked
```

Cross-platform unit tests exercise packet and lifecycle logic under `cfg(test)`. Changes to adapter ownership or underlay binding also require Windows x86_64 platform-workflow evidence.
