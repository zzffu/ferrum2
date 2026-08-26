# Ferrum2 Server Guidelines

## Scope and Boundaries

This package composes the Shadowsocks server. Keep `main.rs` and `cli.rs` limited to argument handling, configuration validation, diagnostics setup, and delegation. Runtime ownership belongs under `run/`: TCP and UDP listeners, DNS egress, observation, I/O, shutdown, and rollback. Move reusable cipher, framing, resolver, routing, or relay behavior into the appropriate `crates/ferrum2-*` package.

`--check-config` is an offline contract. It must accept schema version 2 only, reject older or missing schema versions, and never open listeners, resolve peers, or create runtime resources. Preserve fail-closed startup: if one listener or worker fails, previously acquired resources must be released before exit.

## Testing and Local Commands

Use locked package commands:

```text
cargo test -p ferrum2-server --locked
cargo run -p ferrum2-server --locked -- --help
cargo build -p ferrum2-server --bin ferrum2-server --locked
```

Place focused orchestration tests with the corresponding `run/` module. For externally observable CLI, TCP/UDP, DNS, lifecycle, or interoperability changes, run the matching `tests/m0-harness` target as well as the package tests.

## Runtime and Security Rules

Keep task, socket, session, and shutdown ownership explicit and bounded. Do not introduce protocol fallback after authentication or route selection fails. Errors and telemetry must not expose keys, plaintext, or peer data; use shared redaction and metric types. Preserve clean rebind behavior after shutdown and deterministic cleanup on partial failures. The repository-level `AGENTS.md` continues to apply.

An authenticated Shadowsocks UDP identity performs one route decision when its first valid datagram commits. Freeze the resulting terminal and, for Direct, its outbound across every later target, RuleSet refresh, idle rebuild, and network reset until the protocol identity retires. Later datagrams must not re-run route or sniff evaluation. Resource failure before the first atomic runtime/protocol commit remains non-mutating and does not freeze a candidate route.
