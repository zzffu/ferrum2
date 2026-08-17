# M0 Harness Guidelines

## Purpose and Isolation

This package is the workspace's black-box integration and qualification harness. Keep it independent of concrete `ferrum2-*` Cargo dependencies: tests should exercise built client/server binaries, public configuration, sockets, process state, and qualification seams. Do not include production source files or assert private function names, module layout, call order, or source-text fragments. `workspace_policy.rs` is reserved for structured dependency, toolchain, supply-chain, and unsafe-boundary checks.

Use `src/local_support`, `src/qualification`, and `src/external_support` for shared process and provider mechanics. Tests must allocate isolated loopback resources, use bounded waits, reap children on every path, and leave ports reusable after failure or panic.

## Running Tests

Build product binaries before process-level tests, especially with a clean target directory:

```text
cargo build -p ferrum2-client -p ferrum2-server --bins --locked
cargo test -p ferrum2-m0-harness --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
```

Name integration tests for observable outcomes. Keep ordinary tests portable and unprivileged; hosted-provider, long lifecycle, IPv6-only, or Windows TUN coverage belongs in its designated workflow.

## Evidence and Secrets

Assert exit status, protocol bytes, cleanup state, and structured evidence rather than incidental prose. Never print fixture keys, peer payloads, or provider credentials. Qualification failures must remain row-isolated and cleanup failures must never produce success. The repository-level `AGENTS.md` continues to apply.
