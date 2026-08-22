# Ferrum2 Client Guidelines

## Scope and Boundaries

This package is the client composition root. `main.rs` and `cli.rs` should remain thin: parse `--config` and `--check-config`, initialize diagnostics, and delegate to `run`. Keep orchestration in `run/`, including SOCKS ingress, route selection, DNS egress, TCP/UDP execution, and managed TUN lifecycle. Reusable protocol, crypto, resolver, or transport behavior belongs in its owning `crates/ferrum2-*` package rather than here.

Preserve the separation between validated configuration and runtime resources. `--check-config` must not bind sockets, create adapters, or start workers. Startup failures and partial initialization must roll back listeners, tasks, DNS state, and managed bindings.

## Testing and Local Commands

Run the package checks while iterating:

```text
cargo test -p ferrum2-client --locked
cargo run -p ferrum2-client --locked -- --help
cargo build -p ferrum2-client --bin ferrum2-client --locked
```

Add focused unit tests beside the affected `run/` module. Changes visible across processes, configuration versions, SOCKS, UDP, DNS, or TUN also require the relevant `tests/m0-harness` integration test.

## Safety and Observability

Keep peer addresses, keys, and configuration secrets out of logs and error chains. Use the shared observability facilities and stable error categories. Maintain bounded queues, timeouts, and explicit ownership; do not add detached tasks or fallback paths that bypass validated routing policy. The repository-level `AGENTS.md` continues to apply.

Managed TUN handlers are session-bound and must stop when their session generation is cancelled. A logical UDP TUN association uses endpoint-independent mapping, but every destination still receives an independent route decision and compatible child outbound/underlay binding; never reuse the first destination's terminal for a later destination. Synthetic DNS matching remains exact per datagram or TCP destination and supports either configured address family.

Managed-TUN UDP target children use `reserve_unmetered_datagram` for both request and response buffers, regardless of Direct or Shadowsocks egress. “Unmetered” means only that these buffers do not charge or fail against the shared runtime UDP byte budget; association/session capacity, packet-queue depth, payload length, timeout, and generation checks remain mandatory. SOCKS, DNS, and RuleSet UDP must continue using metered reservations and must retain their existing `BufferLimit` behavior.
