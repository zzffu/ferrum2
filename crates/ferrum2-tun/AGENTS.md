# ferrum2-tun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-tun` owns the private packet-loop supervisor and restartable sessions, the Windows system TCP packet converter and socket leases, canonical packet parsing and fragment reassembly, and the native UDP candidate/association lifecycle. Routing, policy decisions, DNS behavior, and outbound transports belong to callers. Every queue and state table needs clear ownership plus packet-count, entry-count, protocol-length, timeout, and generation bounds. Do not reintroduce smoltcp, a TCP byte bridge, an aggregate TUN byte budget, or a startup memory formula.

The real adapter path exists only on Windows x86_64 through `ferrum2-platform-windows`. Other targets intentionally build a root that fails during preparation. Do not make unsupported targets appear functional. This crate forbids unsafe code; platform FFI remains isolated in `ferrum2-platform-windows`.

Packet admission must stay fail-closed: use one canonical IPv4/IPv6 parser, enforce declared lengths and checksums (including the IPv4 UDP zero-checksum exception), valid unicast endpoints and non-zero ports, extension-header bounds, and strict fragment reassembly limits. Reassemble accepted IPv4 and IPv6 fragments before TCP/UDP policy or checksum handling; reject overlaps and stale generations. Preserve initial-SYN-only TCP admission, flow limits, backpressure, FIN/reset behavior, and owner-thread cleanup. UDP mapping is fixed EIM by local source address, with default endpoint-independent filtering and optional address-dependent filtering. A `UdpCandidate` remains provisional until its generation-checked owner commit; never silently evict a live candidate or association, and never let an old-generation handle mutate or inject into a newer runtime.

Keep `packet.rs` focused on target-neutral parsing and validation. Local ICMP/control generation belongs
in `packet/control.rs`, while packet-only fixtures and unit cases belong in `packet/test_support.rs`
and `packet/tests.rs`. Gate these focused modules at their declaration boundary instead of scattering
the same target predicate across individual packet items.

Ordinary network-semantic changes perform a lightweight `ResetNetwork`: quiesce admission, fence
socket leases abortively, and deliver kernel-generated reset packets through the old tuple mapping
before removing its exact ingress guard. Prior FIN delivery cannot satisfy a new reset obligation.
Stop/join the old listener epoch and remove its guard, then complete the generation barrier/reset
hooks and clear provisional/packet state. A bounded delivery failure cannot advertise successful reset.
Replace the network runtime/stack, bind fresh listener identities, verify peer routes, and install
and read back the new ingress guard before reopening admission. Preserve the long-lived adapter,
Wintun session, GUID/LUID, managed addresses/routes/DNS, strict-route WFP session, and ownership ledger.
Keep TCP identity quarantine in the supervisor across epochs and use its common monotonic clock;
late packets or accepts must never attach to a new flow. Confirmed managed-state damage or immutable
TUN configuration changes use the separate full-rebuild path with reverse cleanup.
Cleanup-integrity failures remain terminal. Wintun ring-full is an explicitly counted packet drop:
do not retry it and do not reset or rebuild for it.

An adapter-creation cleanup failure takes precedence over a simultaneous stop, shutdown or expired
readiness deadline. Invalidate the published underlay before reporting that terminal failure;
cancellation must not turn an unconfirmed cleanup into a successful stopped result.

## TUN-only Performance

The `benchmark` feature and `tun-benchmark` example expose bounded mock I/O, not a working
non-Windows product root. Keep the packet/owner implementation shared with production. Mock only
external packet/connection I/O; do not replace tuple mapping, UDP, reassembly or scheduler logic.
Production builds must not pay for the memory socket adapter. Benchmarking uses no OS socket,
adapter, route, DNS or WFP operations; real-loopback tests separately qualify socket reactor behavior.

Inputs and storage diagnostics are outside measured windows. Capture into bounded preallocated
buffers, validate complete outputs after each batch and count only checked work. Preserve the
controller's exact recipe/source identities and fixed batch schedule. Internal packet costs are not
whole-product throughput; memory observations are not process RSS.

## Focused Verification

Run:

```text
cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked
cargo check -p ferrum2-tun --all-features --locked
cargo build -p ferrum2-tun --example tun-benchmark --no-default-features --features benchmark --profile profiling --locked
```

The library suite is hosted-safe and runs on ordinary Linux and hosted Windows. Keep it target-neutral:
tests may exercise unsupported-target stubs, pure packet/state logic, and injected owner/adapter
operations. The default `live-backend` feature is additive and forwards the platform production
backend; hosted test commands must disable default features so that backend is not compiled into the
test dependency graph. Tests must never create a real adapter or mutate live route, DNS, WFP, or
interface state. Such behavior belongs only in the explicitly acknowledged host qualification runner.

Keep `live-backend` selection at module boundaries. `process` and `network` each choose one live or
hosted implementation; owner-only lifecycle, supervisor, TCP, and runtime code belongs in their
focused runtime/live submodules. Shared packet, stack, cancellation, and socket-lease state must not
grow per-item feature predicates. Platform configuration validity belongs to the platform
constructors; the TUN process layer validates only its own flow, timeout, and mapping resource limits.

The reviewed static packet contract lives in `tests/fixtures/packets/reassembly-v1.hex` with exact provenance in `tests/fixtures/packets/PROVENANCE.toml`. Keep it distinct from the seed sets under `fuzz/corpus/{packet_reassembly,udp_reset_races,config_legacy_fields,strict_route_rules}/`; the reviewed synthetic config and strict-route seeds are recorded in `fuzz/corpus/PROVENANCE.toml`. The fuzz crate has empty default features. Hosted Linux CI may format, check, compile, run the deterministic smoke corpus, and run sanitizer-backed libFuzzer campaigns only against these four pure in-memory targets. The required campaign budget is one hour total, divided equally across the targets, with evolved corpora, logs, and crash artifacts retained as workflow evidence. It must never open a real TUN adapter, start a virtualization workload, mutate host networking, or qualify the unsupported Linux adapter path.
