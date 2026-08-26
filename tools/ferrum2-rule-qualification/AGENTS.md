# Rule Qualification Contributor Guide

The repository-level `AGENTS.md` remains in force. This package owns the executable producer for
deterministic rule, route-program, and DNS-policy qualification evidence. It may enforce producer
correctness, allocation, and same-process parity contracts. Cross-version adoption or regression
thresholds belong to the reviewed external policy and must not be embedded here.

Keep the global `stats_alloc` allocator and allocation measurement lock under one measurement owner.
Latency timing must stay outside allocation regions. Preserve exact JSON field names, ordering,
schema, stdout/file byte equivalence, deterministic fixtures, closed errors, and the existing CLI.
Do not print injected errors, paths beyond the documented repository fingerprint, rule contents,
domains, addresses, or other measurement inputs.

Generated match sets, synthetic and real SRS handling, route programs, and DNS policy each have a
separate owner. Share only the concrete measurement/report contracts they consume; do not introduce
a generic benchmark actor or compatibility façade. Production files stay below 1,000 lines.

Do not run qualification or benchmark workloads during ordinary development. Use compile-only gates:

```text
cargo check -p ferrum2-rule-qualification --all-targets --all-features --locked
cargo test -p ferrum2-rule-qualification --no-run --locked
cargo clippy -p ferrum2-rule-qualification --all-targets --all-features --locked -- -D warnings
```
