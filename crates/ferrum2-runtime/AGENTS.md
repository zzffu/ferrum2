# ferrum2-runtime Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate owns protocol-neutral Tokio orchestration and may depend internally only on `ferrum2-core` and `ferrum2-net`: TCP resolution and dialing, absolute deadlines, fixed-buffer relays, bounded accept supervision, process-root transactions, the bounded metrics endpoint, bounded prefix collection, and UDP session/socket/task capacity. DNS, RuleSet, configuration, platform, protocol parsing, cryptography, replay policy, and telemetry schema belong in their owning crates or binary composition; the metrics renderer is deliberately supplied by composition.

Treat resource ownership as part of every API contract. Preserve permit-before-accept admission, half-close and backpressure behavior, fixed buffer bounds, and `OwnerRegistry` returning to its baseline. Process startup must prepare before activation, roll back in deterministic reverse order, and reap roots exactly once. Shutdown must stop admission, allow bounded draining, then cancel/abort and join remaining owners. Resolution and candidate attempts share one monotonic absolute deadline.

UDP changes must retain the reserve-then-commit protocol seam: provisional sessions, queue slots, sockets, and allocated byte capacity roll back on drop; generation-bound handles reject stale work; protocol commit, activity refresh, and enqueue remain serialized. Do not expose or format injected resolver, socket, handler, or I/O error values through closed runtime errors.

`reserve_datagram_in_budget` charges an independent bounded UDP byte domain while retaining the manager's packet-queue depth, payload length, session capacity, handle validity, and generation checks. Managed TUN shares one independent budget across fixed egress buffers and queued/materialized datagrams; ordinary SOCKS, DNS, and RuleSet UDP remains charged to the ordinary manager budget. No unmetered reservation API is permitted. Dropping reservations must release their exact domain charge and queue/session ownership, while retained payload owners keep their charge until the last allocation owner drops.

Use these focused gates:

```text
cargo test -p ferrum2-runtime --locked
cargo test -p ferrum2-runtime --test lifecycle_accept --locked
cargo test -p ferrum2-runtime --test lifecycle_transaction --locked
cargo test -p ferrum2-runtime --test shutdown --locked
cargo test -p ferrum2-runtime --test udp_reservation --locked
cargo test -p ferrum2-runtime --test udp_session --locked
```

Use paused Tokio time for deadline, idle-expiry, and shutdown-boundary tests; assert final owner counts as well as returned outcomes.
