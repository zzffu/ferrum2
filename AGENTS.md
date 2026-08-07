# Repository instructions

Replace or extend the project-specific sections below with the repository's real
architecture, commands, conventions, and security constraints. Keep version numbers
and command definitions in their authoritative build/config files where possible.

## Project-specific context

- Product:
  - `ferrum2` is a Rust proxy with separate client and server binaries. The
    current release implements SIP022 TCP/UDP for the three standard
    Shadowsocks 2022 methods; public client inbounds expose SOCKS5 TCP CONNECT
    and explicit opt-in UDP ASSOCIATE.
  - Legacy single-instance composition keeps one process-wide PSK/method. Tagged
    client graphs may instead use per-concrete-outbound credentials, bounded fixed
    proxy chains, static bindings or shared exact-target TCP/UDP first-match
    routing. Static and routed actions may name bounded tagged manual selectors;
    the public Rust control atomically switches fixed members while already
    selected flows retain their concrete snapshot. Multiple concrete upstreams,
    chains and selectors do not imply an upstream group or load balancing. Server
    outbounds remain direct; configuration is typed TOML with `tracing` and
    low-cardinality metrics.
  - An optional tagged DNS graph exposes client UDP/TCP DNS proxy inbounds and
    resolves authenticated server domain targets through UDP, TCP, DoT or DoH
    servers. DNS first-match actions are separate from ordinary routing; each DNS
    server may use an existing outbound action as its detour to a numeric bootstrap
    address. Missing `[dns]` preserves legacy system-resolution behavior.
  - Release targets are Linux x86_64 GNU/musl and Windows. License:
    `GPL-3.0-only`.

- Stack and modules:
  - Use stable Rust, Cargo, Tokio, Serde/TOML, owned buffers, and pure-Rust
    dependencies where practical. Versions and MSRV live in workspace files.
  - `ferrum2-core` owns runtime-neutral network interfaces and values;
    `ferrum2-crypto` owns secrets and crypto primitives;
    `ferrum2-shadowsocks` and `ferrum2-socks5` own protocol behavior;
    `ferrum2-dns` owns bounded Hickory integration;
    `ferrum2-runtime` owns bounded I/O and process lifecycle;
    `ferrum2-config` and `ferrum2-observability` own operator surfaces.
    Binaries are composition roots.
  - `ferrum2-crypto` preserves the public crypto seam and uses one exact, patched,
    vendored `shadowsocks-crypto 0.7.0` `v2` backend. Protocol state machines remain
    owned by `ferrum2-shadowsocks`.
  - Keep `core` free of concrete protocols, config formats, and async runtimes.
    Protocol modules do not own routing, process-global state, or CLI policy.
    Reuse `ProcessRoot`/`ProcessSupervisor` for independently managed runtime
    roots.
  - Prefer small, deep interfaces and reusable buffers. Add a seam only when a
    real implementation needs it; current traits and crate topology may evolve
    when tests demonstrate the need.
  - Workspace product code forbids unsafe by default. A narrow exception needs
    a documented rationale, focused tests, and review.

- Security and reliability:
  - SIP022 is defined by <https://shadowsocks.org/doc/sip022.html>. Preserve its
    wire, authentication, replay, nonce, timestamp, and request/response-binding
    rules for every claimed method and transport.
  - Validate key sizes. Never expose secrets in logs, errors, traces, or metrics;
    use CSPRNG material, prevent key/nonce reuse, and zeroize secrets where
    practical.
  - Authenticate and validate peer-controlled lengths/addresses before target
    connection, forwarding, accepted-state mutation, or large allocation. Fail
    closed per flow.
  - Bound sessions, buffers, queues, and idle lifetimes. Every task and resource
    has an owner, cancellation path, and awaited shutdown. Do not block Tokio
    workers.
  - Validate complete configuration before runtime side effects. Preserve
    existing `schema_version = 1` behavior with additive changes; use an
    explicit successor version for breaking semantics.
  - Claimed protocol support requires known-answer, negative, and external
    interoperability coverage. Performance claims require reproducible evidence.

- Evolution:
  - SIP023 and multi-user support are not planned; do not add preparatory
    abstractions without a concrete requirement.
  - Preferred dependency order, adjustable by validated need:
    upstream groups, load balancing and health/failover; Tailscale Endpoint;
    Linux transparent inbound; Windows TUN; hot reload; management API.
  - A future Tailscale Endpoint may expose inbound, outbound, and datagram
    adapters under one tag. Prefer external `tailscaled`/OS routing for simple
    Tailnet access; add an embedded endpoint interface only with a concrete,
    security-reviewed implementation. System TUN, MagicDNS, route advertising,
    exit-node, and SSH support are optional follow-ups.
  - Keep the public `ferrum2-crypto` seam. An external crypto implementation,
    including `shadowsocks-crypto`, may be used internally after security,
    nonce-exhaustion, zeroization, KAT, interoperability, performance, MSRV,
    license, and dependency review. Do not replace the protocol state machines
    with another proxy project's protocol core without an explicit decision.

- Repository hygiene:
  - Commit `Cargo.lock`; do not commit build output, local evidence, real PSKs,
    or production endpoints. Reviewed non-secret protocol fixtures are source.
  - Validation commands live in `docs/agents/milestone-workflow.md`. M0-M12 are
    closed; historical evidence belongs in milestone/history documents, not in
    this context summary.


## Project validation

The authoritative project command lists live in
`docs/agents/milestone-workflow.md`. Document additional package/module-specific
validation rules here.

<!-- BEGIN MILESTONE WORKFLOW -->
## Milestone workflow

Read `.agents/skills/milestone-workflow/SKILL.md` and
`docs/agents/milestone-workflow.md`. Use one ticket/branch/worktree per writer, keep
workflow files read-only during product work, report exact validation results, and do
not push or publish without explicit approval.
<!-- END MILESTONE WORKFLOW -->
