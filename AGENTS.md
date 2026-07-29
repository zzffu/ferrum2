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
  - M3 establishes the accepted `schema_version = 1` operator surface plus its
    CLI, diagnostic, trace, and metric identities as compatibility contracts.
    The current client and server release binaries are qualified on Windows
    MSVC, Linux GNU, and Linux musl; packaging and publication remain separate.
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
  - M0 established the Cargo workspace and first reviewed product slice. The
    root `Cargo.toml` and `Cargo.lock` are authoritative for the current
    workspace; the entry points below are implemented and must remain
    reconciled with those manifests:
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
      relays, bounded session tables, cancellation, and graceful shutdown. Its
      `process` module exposes the topology-neutral `ProcessRoot`,
      `PreparedProcessRoot`, and `ProcessSupervisor` lifecycle used by both
      binaries for prepare, activate, rollback, fatal-root arbitration,
      grace/force shutdown, ownership checks, and bounded reap.
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
  - The client and server `run.rs` composition roots adapt the current single
    listen/server, optional UDP/metrics, and IPv4-validated operator endpoints
    to the shared process lifecycle. These are current adapters, not exhaustive
    future topology.
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
  - The M3-close parser-accepted `schema_version = 1` cohort remains valid
    throughout v0.x. After a stable successor schema, removal additionally
    waits at least 12 months and two stable minor releases and requires notice
    in the preceding stable release. Compatible v1 evolution is optional,
    additive, or a safe widening that preserves omitted-field behavior;
    breaking changes use an explicit new version, never heuristic fallback,
    silent reinterpretation, or automatic rewrite.
  - Complete semantic configuration validation happens before subscriber or
    runtime construction, listeners, sockets, metrics endpoints, session
    state, channels, or tasks. Offline validation is side-effect free. Stable
    CLI exits, closed redacted diagnostic codes and trace fields, and the
    fourteen metric-family identities must not expose secrets or destinations.
  - Every required process root is prepared before any service loop is polled.
    Preparation/activation failure rolls back deterministically in reverse
    order. One transitive owner lineage, monotonic cancellation, one absolute
    grace deadline, explicit force, the fixed five-second forced-root reap
    watchdog, awaited termination, and final owner-baseline equality are
    required; cleanup failure remains explicit and cannot overwrite the primary
    cause.
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
  - The current v0 implementation has no generated source tree. If code
    generation becomes necessary, keep output in Cargo's `OUT_DIR`, document
    the generator and reproducibility contract, and never hand-edit its output.
  - Native release binaries, SHA-256 records, linkage reports, and hosted
    qualification logs are generated evidence. They are not committed source
    or publication artifacts.
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
    Cross-platform native artifact/linkage and pinned external interoperability
    execute in the hosted `.github/workflows/m0.yml` qualification profile and
    `tests/platform/**`; they supplement rather than replace host-local gates.
  - Never commit real PSKs or production endpoints. Examples and tests use
    clearly synthetic keys generated specifically for the repository.
- Active planned changes:
  - None.


## Project validation

The authoritative machine-readable command lists live in `workflow.toml`.
Document any additional package/module-specific validation rules here.

<!-- BEGIN CODEX MILESTONE WORKFLOW -->
## Codex milestone workflow

### Control model

- The primary Codex thread is the Team Lead, sole scheduler, and sole integrator.
- Use `$milestone-workflow` explicitly for bootstrap, feature, plan, execute, status,
  resume, and close modes. Use `feature` for a new capability after prior milestones;
  it auto-allocates the next milestone, refreshes Project-specific context, and plans.
- Delegate outcome/scope analysis to `product_manager`, architecture and bounded
  design review to `architect`, one-ticket implementation to `engineer`, and
  evidence/gate execution to `qa`.
- Subagents do not spawn other subagents, merge branches, publish work, or mutate
  workflow coordination state.
- `strategy = "drain"` means one execute invocation keeps scheduling all later
  dependency-ready waves until ready-to-close or a material stop condition.

### Control-plane boundary

The installed workflow is infrastructure, not product scope. During bootstrap,
feature, plan, execute, resume, and close, do not edit any `.agents/skills/**`,
`.codex/agents/**`, `.codex/config.toml`, `workflow.toml`, the install manifest, or the
nested control-plane `AGENTS.override.md` files. The delimited workflow-policy block
in this file is package-owned; only `## Project-specific context` is updated during
product work. Run `workflow.py control-plane-check`
before scheduling and integration. Record a missing capability in
`docs/workflow-debt.md` and stop with `CONTROL_PLANE_CHANGE_REQUIRED`; change the
workflow only in a separate explicit maintenance/upgrade task.

### Sources of truth and contract scope

Read the nearest applicable `AGENTS.md`, `workflow.toml`, vision/roadmap, relevant
ADR/spec/test-plan/ticket files, source code, tests, and CI definitions.

`## Project-specific context` is maintained repository truth. Before planning a new
feature and at milestone close, inventory every configured and project-added top-level
entry, compare it with exact repository evidence, write a context audit, and update the
section. Current shipped facts stay separate from `Active planned changes`; a requested
feature is `planned` until its integrated closeout proves otherwise. The Team Lead is
the only writer of AGENTS.md.

Contracts are outcome-oriented. They may constrain observable behavior, interfaces,
invariants, compatibility, migration, errors, and acceptance evidence. They must not
prescribe every helper, branch, or test layer. Execute freezes approved MUST
requirements, ADR decisions, ticket scope, and acceptance criteria. A new blocking
contract requires evidence that the existing contract is contradictory, unsafe, or
impossible, plus explicit user approval.

### Planning and ticket economy

- Prefer small independently verifiable vertical slices.
- Respect `planning.max_adrs_per_milestone`, document soft limits, and
  `planning.max_acceptance_criteria_per_ticket`.
- Separate implementation, review, integration, and release dependencies.
- Give every ticket explicit, non-overlapping `owns` paths.
- Map each MUST/acceptance criterion to one primary evidence item. Add another layer
  only for a distinct named failure mode not observable at the primary seam.

### Selective TDD and test budget

- TDD is selective, not a test-count objective. Use red-green-refactor for changed
  behavior, regressions, and hard invariants when a failing test is the clearest seam.
- Search for an existing table, fixture, or integration seam before creating a new
  test file or harness.
- Do not create one test per sentence, branch, helper, reviewer suggestion, or layer.
- Do not test a test harness unless it is a supported artifact or has a demonstrated
  failure mode.
- Product gates prove ticket behavior; integration gates prove cross-ticket
  interaction; hosted/platform/soak/external-service evidence belongs to release
  qualification unless the ticket implements that behavior.
- Run `workflow.py test-budget --gate ticket` before integration and
  `--gate milestone` at close. Existing high-ratio repositories use a non-regression
  ratchet baseline; never improve the ratio by adding meaningless production code.

### Bounded review convergence

- Architect/QA reviews in this workflow are the authoritative milestone gates.
- Each required reviewer gets one full review bound to the exact candidate SHA.
- Only `blocker` and `major` findings block. Use stable finding IDs and one canonical
  root cause; derivative failures do not become separate repair loops.
- A full `BLOCK` permits exactly one substantive repair. Mechanical cleanup does not
  consume that repair but does not restart a full review.
- The same reviewer then gets one targeted re-review limited to original blocking
  IDs, the repair delta, and invalidated tests.
- A second blocking result is `ESCALATE`; do not start a third automatic review or
  repair cycle. A later integration/release root becomes a new repair ticket, not a
  superseding review or append-only review cycle on the completed ticket.
- `PASS_WITH_NOTES` integrates and records non-blocking debt in
  `docs/review-debt.md`.
- Do not implicitly invoke a separate generic `code-review` Skill during execute.
  Explicit user-requested independent review remains available but cannot silently
  reopen the milestone loop.

### Parallel work and Git safety

- Parallelize independent read-heavy work freely.
- Never run two write-heavy agents in one worktree.
- Every Engineer receives one ticket, one branch, one absolute worktree, approved
  contract paths, ownership paths, and validation commands.
- Only dependency-ready tickets with disjoint ownership may run in parallel; unknown
  ownership is overlapping.
- Engineers never merge, rebase, push, force-push, delete branches, or edit the base
  worktree. Stage explicit files; do not use `git add .`.
- Team Lead integrates first into the milestone integration worktree, runs gates, and
  fast-forwards the clean base only when the base has not moved.
- Never discard unknown changes, run destructive reset/clean commands, or mutate
  remote state without separate explicit authorization.

### Evidence and completion report

Never claim a command, review, or gate ran when it did not. Every milestone response
must report context-audit and AGENTS.md changes, files/documents changed,
tickets/branches/worktrees, full and targeted
review records, stable finding IDs, exact validation commands and exit statuses,
test-budget counts and baseline, commits/integration state, blockers/debt/deferred
work, and whether anything was pushed or published (default: no).
<!-- END CODEX MILESTONE WORKFLOW -->
