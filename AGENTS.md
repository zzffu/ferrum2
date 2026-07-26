# Repository instructions

Replace or extend the project-specific sections below with the repository's real
architecture, commands, conventions, and security constraints. Keep version numbers
and command definitions in their authoritative build/config files where possible.

## Project-specific context

- Product purpose:
  - `ferrum2` is a high-performance, extensible proxy implemented in Rust. It
    ships separate `ferrum2-client` and `ferrum2-server` binaries.
  - Version 0 independently implements Shadowsocks 2022 (SIP022) for TCP and
    UDP. The supported methods are `2022-blake3-aes-128-gcm`,
    `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`.
    Reduced-round ChaCha methods are out of scope.
  - The v0 client exposes SOCKS5 TCP `CONNECT`. The Shadowsocks protocol layer
    still implements TCP and UDP, but v0 does not claim a user-facing UDP
    inbound such as SOCKS5 `UDP ASSOCIATE`.
  - The server uses a minimal direct outbound to connect to requested targets.
    Routing rules, a DNS proxy/resolver, multiple upstreams, load balancing,
    proxy chaining, hot reload, and a management API are out of scope for v0.
  - V0 uses one PSK. Multi-user operation and SIP023 Extensible Identity
    Headers are deferred, but the key lookup boundary must allow them to be
    added without rewriting the transport state machines.
  - Both client and server use typed TOML configuration, structured `tracing`
    logs, and bounded-cardinality Prometheus metrics. Each binary must be able
    to validate configuration without starting listeners.
  - Required release targets are Linux x86_64 with glibc, Linux x86_64 with
    musl, and Windows. The project is licensed `GPL-3.0-only`.

- Primary languages/frameworks:
  - Use stable Rust in a Cargo workspace. Pin the MSRV and dependency versions
    in the workspace manifests rather than in this file.
  - Use Tokio's multi-thread runtime for asynchronous I/O, `bytes`-style owned
    buffers, and `socket2` where explicit socket configuration is needed.
    A custom executor and `io_uring` backend are not part of v0.
  - Prefer pure-Rust cryptographic dependencies. Implement the SIP022 protocol
    from its specification; do not depend on another proxy project's
    Shadowsocks protocol core.
  - Set workspace-level `unsafe_code = "forbid"`. An exception requires a
    separately isolated performance crate, benchmark evidence, an approved
    safety rationale/ADR, and focused review.
  - Use Serde-backed TOML configuration, `tracing` for structured diagnostics,
    and a Prometheus-compatible metrics implementation. Secrets and destination
    values must not become metric labels.

- Architecture entry points:
  - This repository currently contains the workflow control plane only; no
    Cargo workspace has been scaffolded. The planned workspace entry points
    below must be reconciled with the root `Cargo.toml` when the first vertical
    slice is created:
    - `bins/ferrum2-client`: composition root for the SOCKS5 client.
    - `bins/ferrum2-server`: composition root for the Shadowsocks server and
      direct outbound.
    - `crates/ferrum2-core`: network/address types plus the protocol-neutral
      `Inbound`, `Outbound`, `Session`, and `Connector` contracts.
    - `crates/ferrum2-crypto`: secret handling, SIP022 key derivation, and
      audited AEAD primitives; it contains no socket or policy code.
    - `crates/ferrum2-shadowsocks`: SIP022 TCP/UDP framing, codecs, replay
      protection, and transport state machines.
    - `crates/ferrum2-socks5`: SOCKS5 parsing and the v0 TCP `CONNECT` inbound.
    - `crates/ferrum2-runtime`: listener orchestration, connection/datagram
      relays, bounded session tables, cancellation, and graceful shutdown.
    - `crates/ferrum2-config`: TOML deserialization and complete semantic
      validation before runtime resources are created.
    - `crates/ferrum2-observability`: log/metric initialization and stable,
      low-cardinality instrumentation.
  - `Inbound` accepts application-facing traffic and produces a normalized
    `Session`; `Outbound` handles that session; `Connector` establishes the
    required stream or datagram path. Protocol crates must not own routing
    policy, process-global runtime state, or CLI concerns.
  - Keep dependencies one-way from binaries/runtime toward protocol and core
    crates. `ferrum2-core` must not depend on a concrete inbound, outbound,
    cipher, configuration format, or async runtime implementation.
  - Prefer static dispatch and reusable buffers in per-connection and
    per-packet hot paths. Trait objects are acceptable at composition seams,
    not automatically inside every frame or datagram operation.

- Critical invariants:
  - The normative wire contract is
    <https://shadowsocks.org/doc/sip022.html>. Compatibility behavior may be
    studied in sing-box and shadowsocks-rust, but copied code requires explicit
    provenance and license review.
  - Base64-decoded PSKs must have the exact size required by the selected
    method. Keys, derived keys, salts, nonces, and secret-bearing configuration
    must never appear in logs, errors, panic messages, traces, or metric labels.
    Wrap secret material in secret types and zeroize it where practical.
  - Use a CSPRNG for salts, session IDs, nonces, padding, and other protocol
    randomness. Never reuse a TCP salt or a UDP nonce/session identifier in a
    way that repeats an AEAD key/nonce pair; packet IDs are monotonic within
    their session and direction.
  - Enforce SIP022 message types, key derivation, framing, request/response
    binding, and detection-prevention behavior exactly. A timestamp more than
    30 seconds from system time is a replay and must be rejected.
  - The server retains received TCP salts for at least 60 seconds in an exact
    replay set; probabilistic structures with false positives are forbidden.
    UDP sessions retain the protocol-required replay state for at least 60
    seconds, use per-direction sliding windows, and update those windows only
    after successful authentication and semantic header validation.
  - Authentication and all length/address bounds checks happen before target
    connection, allocation based on peer-controlled sizes, forwarding, or
    mutation of accepted-session state. Authentication or validation failure
    fails closed and terminates only the affected flow.
  - UDP session counts, buffered bytes, and idle lifetimes have explicit limits.
    All channels and queues are bounded, and backpressure propagates end to end.
    No input-dependent unbounded allocation is permitted.
  - Every spawned task has an owner and a termination path. Cancellation,
    timeout, TCP half-close, listener failure, and graceful shutdown must not
    leak tasks, sockets, buffers, or UDP sessions.
  - Do not block Tokio worker threads. Avoid per-packet heap allocation and
    copying where ownership can be transferred safely, but never trade away
    authentication, replay protection, bounds checking, or backpressure for a
    benchmark result.
  - Interoperability is a release gate: for every supported cipher and
    transport, test ferrum2 client against sing-box and shadowsocks-rust
    servers, and their clients against ferrum2 server. UDP coverage may use the
    protocol API until a public UDP inbound exists.
  - Establish reproducible, pinned benchmark configurations before making
    performance claims. The initial target is at least 90% of the comparable
    shadowsocks-rust loopback aggregate TCP throughput on the same host, plus
    stable task and memory usage with 10,000 idle TCP sessions.

- Generated files:
  - Cargo build output under `target/`, coverage/profiling output, benchmark
    results, packet captures, logs, and locally rendered documentation are
    generated artifacts and must not be committed.
  - Commit the workspace `Cargo.lock`, because ferrum2 ships applications.
  - There is no generated source tree in the planned v0 architecture. If code
    generation becomes necessary, keep output in Cargo's `OUT_DIR`, document
    the generator and reproducibility contract, and never hand-edit its output.
  - Protocol known-answer vectors and interoperability fixtures are reviewed
    test inputs, not disposable build output. Commit only non-secret fixtures
    with their source and expected result documented.

- Local development setup:
  - Install the stable Rust toolchain with the `rustfmt` and `clippy`
    components. Install the target toolchains/linkers needed for the supported
    Linux glibc, Linux musl, and Windows builds.
  - Use Cargo directly; do not introduce Just, Make, Docker Compose, Nix,
    cargo-nextest, cargo-deny, cargo-audit, or another task runner as a required
    local workflow without an explicit project decision.
  - The authoritative quick and full command lists are in `workflow.toml`.
    Run the quick gate during development and the full gate before integration.
    Cross-platform and external interoperability jobs supplement these
    host-local commands once their test harnesses exist.
  - Never commit real PSKs or production endpoints. Examples and tests use
    clearly synthetic keys generated specifically for the repository.

## Project validation

The authoritative machine-readable command lists live in `workflow.toml`.
Document any additional package/module-specific validation rules here.

<!-- BEGIN CODEX MILESTONE WORKFLOW -->
## Codex milestone workflow

### Control model

- The primary Codex thread is the Team Lead and sole integrator.
- Use the `milestone-workflow` skill for milestone bootstrap, planning, execution,
  status, recovery, and closeout.
- Delegate product planning to `product_manager`, system design/review to
  `architect`, implementation to `engineer`, and test gates to `qa`.
- Subagents return evidence to the Team Lead. They do not schedule other agents,
  merge, or publish work.
- In `execute` mode, the default `drain` strategy keeps recomputing frontiers and
  scheduling later dependency waves in the same primary-thread invocation. The user
  does not need to invoke `execute` once per frontier.

### Sources of truth

Read these before milestone work:

1. The nearest applicable `AGENTS.md` or `AGENTS.override.md`.
2. `workflow.toml` for branch, worktree, document, and validation configuration.
3. `docs/vision.md` and `docs/roadmap.md` for product and milestone intent.
4. Applicable files under `docs/adr/`, `docs/specs/`, `docs/test-plans/`, and
   `docs/tickets/`.
5. The real source code, tests, build files, and CI definitions.

Approved ADRs and specs are contracts. Do not silently rewrite them to justify an
implementation. When implementation evidence invalidates a decision, stop the gate
and propose an explicit ADR/spec revision.

### Required gates

For cross-module, protocol, persistence, public API, security, concurrency, or
hard-to-reverse changes:

1. Product scope and measurable exit criteria.
2. Architecture decision where required.
3. Implementation-ready spec.
4. Test plan mapped to acceptance criteria and failure modes.
5. Tickets with explicit blockers and non-overlapping ownership paths.
6. Implementation in isolated Git worktrees.
7. Architect and QA review.
8. Integration branch validation.
9. Team Lead fast-forward into the base branch only after all gates pass.

Small local fixes may use a reduced path, but still require a precise acceptance
criterion, focused tests, and repository validation.

### Parallel work and Git rules

- Parallelize read-heavy investigation freely when the questions are independent.
- Never run two write-heavy agents in the same worktree.
- Every Engineer receives one ticket, one branch, one worktree, and explicit
  ownership paths.
- Parallel Engineer tickets must have all blockers complete and disjoint ownership
  paths. Unknown or overlapping ownership means sequential execution.
- Engineers may commit only their assigned branch. They may not merge, rebase,
  push, force-push, delete branches, or modify the base worktree.
- The Team Lead integrates into a milestone integration branch/worktree first.
- After each validated wave, the Team Lead checkpoints state and immediately schedules
  the next ready wave when execution strategy is `drain`.
- Do not use `git add .`. Stage files intentionally.
- Never discard an uncommitted change, abort another agent's operation, or run a
  destructive Git command without explicit user authorization.
- Never push, open/merge a PR, publish a release, or mutate remote issue state unless
  the user explicitly requests that separate action.

### Implementation and validation

- Prefer vertical slices with observable behavior over horizontal scaffolding.
- Use red-green-refactor at agreed test seams.
- Treat configured validation commands as deterministic gates; record commands and
  exit statuses.
- A missing or skipped required command is not a pass.
- Keep unrelated cleanup outside the ticket unless separately approved.
- Do not place credentials, private endpoints, production data, or secrets in code,
  tests, fixtures, logs, or documents.

### Optional Matt Pocock skills

When installed, use model-invoked skills as supporting disciplines:
`research`, `prototype`, `domain-modeling`, `codebase-design`, `tdd`,
`diagnosing-bugs`, `code-review`, and `resolving-merge-conflicts`.

Do not recursively invoke another user-invoked orchestration skill from
`milestone-workflow`. The user may run `grill-with-docs`, `wayfinder`, `to-spec`,
`to-tickets`, `implement`, or `handoff` manually before or between workflow modes.

### Completion report

Every implementation or milestone response must state:

- documents and files changed
- tickets and branches involved
- tests and validation commands actually run
- commit IDs and integration state
- unresolved risks, blockers, and deferred work
- whether anything was pushed or published (default: no)
<!-- END CODEX MILESTONE WORKFLOW -->
