# ferrum2-runtime Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate owns protocol-neutral Tokio orchestration: TCP resolution and dialing, absolute deadlines, fixed-buffer relays, bounded accept supervision, process-root transactions, the bounded metrics endpoint, bounded prefix collection, and UDP session/socket/task capacity. Protocol parsing, cryptography, replay policy, and telemetry schema belong in their respective crates; the metrics renderer is deliberately supplied by composition.

Treat resource ownership as part of every API contract. Preserve permit-before-accept admission, half-close and backpressure behavior, fixed buffer bounds, and `OwnerRegistry` returning to its baseline. Process startup must prepare before activation, roll back in deterministic reverse order, and reap roots exactly once. Shutdown must stop admission, allow bounded draining, then cancel/abort and join remaining owners. Resolution and candidate attempts share one monotonic absolute deadline.

UDP changes must retain the reserve-then-commit protocol seam: provisional sessions, queue slots, sockets, and allocated byte capacity roll back on drop; generation-bound handles reject stale work; protocol commit, activity refresh, and enqueue remain serialized. Do not expose or format injected resolver, socket, handler, or I/O error values through closed runtime errors.

`reserve_unmetered_datagram` bypasses only the shared UDP byte counter and `BufferLimit`; it must still enforce packet-queue depth, payload length, session capacity, handle validity, and generation checks. Restrict it to callers such as managed TUN that maintain independent structural packet/queue bounds. Ordinary SOCKS, DNS, and RuleSet UDP remains metered, and dropping either reservation kind must preserve exact queue/session ownership and leave `reserved_bytes` unchanged or restored as appropriate.

Use these focused gates:

```text
cargo test -p ferrum2-runtime --locked
cargo test -p ferrum2-runtime --test lifecycle --locked
cargo test -p ferrum2-runtime --test shutdown --locked
cargo test -p ferrum2-runtime --test udp_runtime --locked
```

Use paused Tokio time for deadline, idle-expiry, and shutdown-boundary tests; assert final owner counts as well as returned outcomes.
