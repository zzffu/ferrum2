# `ferrum2-core` Contributor Guide

This file supplements the repository-level `AGENTS.md` for changes under this crate.

## Responsibility and Boundaries

Keep this crate runtime- and protocol-neutral. It owns validated targets and datagrams, transport composition traits, ordered routing, immutable egress plans, and atomically controlled selector graphs. Socket I/O, Tokio ownership, protocol framing, DNS, and configuration parsing belong in downstream crates. Avoid adding dependencies that pull those concerns into the core contract.

## Verification

Run:

```text
cargo test -p ferrum2-core --locked
cargo test -p ferrum2-core --test route_program --locked
cargo test -p ferrum2-core --test selector_contract --locked
```

Add focused unit coverage for primitive invariants and public contract coverage for routing or concurrent selector behavior.

## Security and Compatibility Contracts

Targets must remain non-printable: do not add `Display`, and keep `Debug` output for targets, datagrams, routes, selectors, and plan snapshots redacted. Preserve ASCII-only domain storage (1–255 bytes), non-zero ports, caller-enforced datagram payload bounds, and captured allocation-capacity accounting.

Routing is ordered first-match with a mandatory final action. Values inside one matcher field are ORed; distinct fields are ANDed. General domain matchers normalize case and one trailing dot, while IP, port, and legacy target matching continue to use the original target. Sniffed domains may refine only domain matching. Keep public 64-rule/value/selector/member limits, non-empty plans, cycle and reachability rejection, complete immutable snapshots, and atomic selector switches that never expose partial plans.
