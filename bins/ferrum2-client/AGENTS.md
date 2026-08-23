# Ferrum2 Client Guidelines

## Scope and Boundaries

This package is the client composition root. `main.rs` and `cli.rs` should remain thin: parse `--config` and `--check-config`, initialize diagnostics, and delegate to `run`. Keep orchestration in `run/`, including SOCKS ingress, route selection, DNS egress, TCP/UDP execution, and managed TUN lifecycle. Reusable protocol, crypto, resolver, or transport behavior belongs in its owning `crates/ferrum2-*` package rather than here.

Preserve the separation between validated configuration and runtime resources. `--check-config` must not bind sockets, create adapters, or start workers. Startup failures and partial initialization must roll back listeners, tasks, DNS state, and managed bindings.

## Testing and Local Commands

Run the package checks while iterating:

```text
cargo test -p ferrum2-client --locked --no-run
cargo run -p ferrum2-client --locked -- --help
cargo build -p ferrum2-client --bin ferrum2-client --locked
```

Add focused unit tests beside the affected `run/` module. Changes visible across processes, configuration versions, SOCKS, UDP, DNS, or TUN also require the relevant `tests/m0-harness` integration test.
Execute every TUN-related test binary and privileged qualification profile only in the pinned local
Hyper-V guest. Host iteration may compile those tests with `--no-run`, but must not create or alter a
host TUN, route, DNS lease, firewall rule, or WFP object.

## Safety and Observability

Keep peer addresses, keys, and configuration secrets out of logs and error chains. Use the shared observability facilities and stable error categories. Maintain bounded queues, timeouts, and explicit ownership; do not add detached tasks or fallback paths that bypass validated routing policy. The repository-level `AGENTS.md` continues to apply.

Managed TUN handlers are reset-generation-bound and must stop when their generation is cancelled. A
logical UDP TUN association uses endpoint-independent mapping. Its first ordinary datagram performs
the only route decision and freezes the terminal, outbound chain, interface policy, and route
generation for every later target on that local source. Synthetic DNS matching remains exact per
datagram or TCP destination, supports either configured address family, and runs before an ordinary
UDP association is frozen.

Managed-TUN UDP associations use `reserve_unmetered_datagram` for request and response buffers,
regardless of Direct or Shadowsocks egress. “Unmetered” means only that these buffers do not charge
or fail against the shared runtime UDP byte budget; association/session capacity, packet-queue
depth, payload length, timeout, and generation checks remain mandatory. SOCKS, DNS, and RuleSet UDP
must continue using metered reservations and must retain their existing `BufferLimit` behavior.
