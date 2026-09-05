# `ferrum2-rule` Contributor Guide

This file supplements the repository-level `AGENTS.md`.

## Responsibility and Boundaries

This crate owns compiled ordinary and RuleSet match sets. `program/{matcher,index,evaluation}` owns
ordered first-match compilation, candidate indexing, continuation, and reusable zero-allocation
scratch; `srs/decode` owns strict framing, bounded primitive reads, rule parsing, and domain/IP set
construction. Egress selectors and plan construction use the runtime-neutral core owner through
this crate's curated exports.
It may depend on runtime-neutral target and egress-plan types from `ferrum2-core`; core must
never depend on this crate. Configuration parsing, socket I/O, DNS queries, and remote
resource lifecycle belong to their owning crates.

`srs/limits` owns the closed per-file policy; `srs/decode/context` owns cumulative accounting
and byte-limited readers. Every `decode_srs` caller supplies explicit `SrsDecodeLimits`.
Admit counts before reserve, count attempted entries before dedup, retain strict framing at exact
byte limits, and emit succinct keys directly to their collector. Do not reintroduce an unlimited
decoder overload. Decoder allowances do not establish matcher, snapshot, download or cache RSS.

## Verification

Run:

```text
cargo test -p ferrum2-rule --locked
cargo test -p ferrum2-config --locked
```

Preserve first-match and continuation ordering, distinct-field AND and within-field OR,
sniffed-domain-only refinement, mandatory finals, zero-allocation matching with prepared
scratch, and redacted formatting.
