# `ferrum2-rule` Contributor Guide

This file supplements the repository-level `AGENTS.md`.

## Responsibility and Boundaries

This crate owns compiled ordinary and RuleSet match sets, ordered first-match programs,
candidate indexes, reusable evaluation scratch, and selector-aware compatibility routing.
It may depend on runtime-neutral target and egress-plan types from `ferrum2-core`; core must
never depend on this crate. Configuration parsing, socket I/O, DNS queries, and remote
resource lifecycle belong to their owning crates.

## Verification

Run:

```text
cargo test -p ferrum2-rule --locked
cargo test -p ferrum2-config --locked
```

Preserve first-match and continuation ordering, distinct-field AND and within-field OR,
sniffed-domain-only refinement, mandatory finals, zero-allocation matching with prepared
scratch, and redacted formatting.
