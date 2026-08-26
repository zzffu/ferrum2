# Ferrum2 Client Guidelines

## Scope and Boundaries

This package is the client composition root. `main.rs` and `cli.rs` should remain thin: parse `--config` and `--check-config`, initialize diagnostics, and delegate to `run`. Keep orchestration in `run/`, including SOCKS ingress, route selection, DNS egress, TCP/UDP execution, and managed TUN lifecycle. Reusable protocol, crypto, resolver, or transport behavior belongs in its owning `crates/ferrum2-*` package rather than here.

Preserve the separation between validated configuration and runtime resources. Plain `--check-config`
is offline. The explicit `--check-config --materialize` mode may resolve fixed endpoints and load
RuleSets, but it must never bind listeners, create a TUN adapter or managed network state, or start
steady-state workers. It must join every temporary resolver, download, and refresh owner before
returning, restore the owner registry to its baseline, and retain the client materialization-failure
exit code of 1. Startup failures and partial initialization must roll back listeners, tasks, DNS
state, and managed bindings.

The materialization handoff uses closed phases: RuleSets are either absent or own one pending
construction plan, run parts are named, and a refresh root is either prepared or cleaned. Keep the
tagged resolver and its owner in one closed transport state; do not reintroduce paired `Option`
fields, positional run tuples, no-await async validation, or a nullable refresh service.

Within `run/egress`, `network.rs` owns physical connector policy, socket generation, and reset
fan-out; `context.rs` owns validated outbound and request-origin vocabulary; `engine.rs` owns route
classification and TCP/UDP dispatch. TCP keeps transport opening in its module. UDP keeps socket
construction, Direct candidate/response behavior, association lifetime, request/session admission,
and response commit in their named owners. Preserve route-once selection, exact buffer metering,
generation binding, synthetic DNS response matching, and fail-closed no-fallback behavior when
moving code between those owners.

Within `run/socks`, keep listener/root ownership, TCP command execution, UDP endpoint I/O,
source-port pinning, association relay, and DNS hijack in their named modules. A zero-port UDP
association pins only after the first accepted valid datagram; wrong-source, malformed, fragmented,
rejected, or over-limit packets must not pin it. Control EOF/reset, idle expiry, generation reset,
and process cancellation must release the association, buffers, and socket together.

Within `run/tun`, keep process-root composition, managed network lifecycle/reset, observation
mapping, TUN TCP policy, and UDP route/DNS/association policy in their named owners. Do not copy or
shadow `ferrum2-tun` packet parsing, peer table, or data-plane state. Synthetic DNS is evaluated for
each destination before ordinary association freezing; the first ordinary datagram freezes terminal,
outbound, interface policy, route generation, and network generation. Unmetered TUN UDP buffers may
bypass only the shared byte budget, never session, queue, payload, generation, or cleanup bounds.

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
