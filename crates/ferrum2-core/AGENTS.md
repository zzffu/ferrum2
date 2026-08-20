# `ferrum2-core` Contributor Guide

This file supplements the repository-level `AGENTS.md` for changes under this crate.

## Responsibility and Boundaries

Keep this crate runtime- and protocol-neutral. It owns validated targets and datagrams, transport composition traits, immutable egress plans, and atomically controlled selector graphs. Rule matching and ordered programs belong in `ferrum2-rule`; core must not depend on that crate. Socket I/O, Tokio ownership, protocol framing, DNS, and configuration parsing belong in downstream crates. Avoid adding dependencies that pull those concerns into the core contract.

## Verification

Run:

```text
cargo test -p ferrum2-core --locked
cargo test -p ferrum2-core --test route_program --locked
cargo test -p ferrum2-core --test selector_contract --locked
```

Add focused unit coverage for primitive invariants and public contract coverage for egress graphs or concurrent selector behavior.

## Security and Compatibility Contracts

Targets must remain non-printable: do not add `Display`, and keep `Debug` output for targets, datagrams, routes, selectors, and plan snapshots redacted. Preserve ASCII-only domain storage (1–255 bytes), non-zero ports, caller-enforced datagram payload bounds, and captured allocation-capacity accounting.

Canonical policy domains normalize ASCII case and one trailing dot while retaining the validated original protocol spelling. Keep inbound/outbound, selector, and selector-member resource limits, non-empty plans, cycle and reachability rejection, complete immutable snapshots, and atomic selector switches that never expose partial plans.
