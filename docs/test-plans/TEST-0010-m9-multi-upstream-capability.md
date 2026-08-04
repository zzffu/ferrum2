# TEST-0010 — M9 multi-upstream 零代码核验

- **Status:** Approved / complete
- **Milestone:** M9
- **Accepted exact:** `5b0a8020e5dac1a915dc64c8229ddd129dd4da4a`

## Evidence map

| Requirement | Primary evidence | Command |
|---|---|---|
| M9-MUST-01 | routed config resolves multiple client outbounds | `cargo test -p ferrum2-config --test config_contract routed_graph_compiles_resolved_first_match_tables_for_both_roles --locked -- --exact` |
| M9-MUST-02 TCP | client selection seam plus two-upstream real-process matrix | `cargo test -p ferrum2-client run::tests::routed_tcp_selects_after_target_and_never_falls_back --locked -- --exact`；`cargo test -p ferrum2-m0-harness --test local_e2e tagged_two_by_two_tcp_matrix_covers_all_methods_and_exact_rebind --locked -- --exact --nocapture` |
| M9-MUST-02 UDP | endpoint-leg seam plus one association alternating two real servers | `cargo test -p ferrum2-client run::tests::routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses --locked -- --exact`；`cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e one_association_alternates_two_targets_and_preserves_response_sources --locked -- --exact --nocapture` |
| M9-MUST-03 | existing no-fallback and cross-leg negative rows；Architect inspection | focused commands above；`cargo test --workspace --all-features --locked` |
| M9-MUST-04 | empty product/test diff and zero footprint deltas | `git diff --exit-code 926843d61fcfac094765b5d1032b7239e3d9370c..5b0a8020e5dac1a915dc64c8229ddd129dd4da4a -- bins crates tests Cargo.toml Cargo.lock rust-toolchain.toml`；`bash scripts/test-budget.sh milestone --candidate 5b0a8020e5dac1a915dc64c8229ddd129dd4da4a` |

## Additional failure modes

- Required real-process binaries absent is setup failure，not PASS or product failure。The workspace
  bin build MUST complete before process tests；the unchanged command then MUST pass。
- Rust unit test filters MUST include the full `run::tests::...` path when combined with
  `--exact`；a zero-test result is not evidence。

## Repository gates

Run serially on the accepted exact：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate 5b0a8020e5dac1a915dc64c8229ddd129dd4da4a
git diff --check
```

All commands passed。No new test case、support、fixture or harness is added；forecast and actual
test footprint growth are `0/0/0`。
