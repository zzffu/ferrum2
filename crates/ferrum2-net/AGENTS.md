# ferrum2-net Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate owns platform-neutral network
contracts and immutable selection models: interface observations, snapshots, dial and route
options, target-aware interface resolution, bounded generation-local resolution caching, host
resolver capabilities, and the already-resolved socket-binding seam.

Keep this crate independent of Tokio task ownership, DNS policy, RuleSet loading, reset
coordination, platform APIs, TUN lifecycle, and application composition. Resolution must preserve
the exact priority order: outbound-explicit, snapshot automatic, route default, then one
target-aware system-best-route query. A physical attempt must carry one immutable snapshot and one
resolved interface decision through binding; binders must never perform another route lookup.

Preserve family validation, stable interface identity, source-address membership, monotonic
generation behavior, the 256-entry successful-resolution cache bound, and closed redacted errors.
Use focused package tests before validating runtime and platform consumers:

```text
cargo test -p ferrum2-net --locked
```
