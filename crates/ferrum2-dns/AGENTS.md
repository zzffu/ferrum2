# `ferrum2-dns` Contributor Guide

This file supplements the repository-level `AGENTS.md` for changes under this crate.

## Responsibility and Boundaries

This crate owns DNS execution without a configuration back-edge. `runtime_owner` owns the resolver handle, commands, and joined command loop; `runtime_provider` owns egress capability, admission/tracking, and the Hickory adapter; `policy` owns the runtime-neutral model compiler, evaluation, and reusable scratch; and `proxy` owns construction, policy-cache adaptation, and the paired UDP/TCP loops. `ferrum2-config` validates schema and emits rule blueprints, while this crate consumes numeric addresses, authenticated transport parameters, rule snapshots, and optional egress plans. Keep relay and detour implementation behind `DnsEgress`.

## Verification

Run the authoritative package gate, including its private interop trust root:

```text
cargo test -p ferrum2-dns --features __interop-test-root --locked
cargo test -p ferrum2-dns --test tagged_upstreams --locked
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-dns --test resource_lifecycle --locked
```

The shared `tests/fixtures/dns-tls` DER/PKCS#8 fixtures are synthetic local-server credentials.
Preserve their hashes, `resolver.test` identity, provenance, and test-only status; never use
`__interop-test-root` as production trust policy.

## Security and Lifecycle Contracts

Queries use one selected server, one aggregate admission permit, and one absolute deadline. Keep Hickory caching, hosts-file lookup, retries, and server races disabled; UDP truncation may upgrade only to TCP on the same server. DoT/DoH must authenticate server names and preserve validated HTTPS paths. Preserve closed, peer-redacting `DnsError` values.

Dropping `TaggedResolver` requests shutdown but is nonblocking; the owner must remain retryably awaitable off-worker. Every query, Hickory task, stream, socket, detour bridge/session, queue, and buffer must be registered, cancelled, joined, and reported at zero on successful shutdown. Proxy framing, connection limits, malformed-message handling, and UDP response truncation must stay bounded.
