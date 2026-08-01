# Milestone workflow settings

- Base branch: `master`
- Worktree root: `.worktrees`
- Max parallel engineers: 3

## Paths

- Milestones: `docs/milestones`
- Tickets: `docs/tickets`
- ADRs: `docs/adr`
- Specs: `docs/specs`
- Test plans: `docs/test-plans`
- Handoffs: `docs/handoffs`
- History: `docs/history`

## Quick validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test --workspace --locked
```

## Full validation

Run serially.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
```
