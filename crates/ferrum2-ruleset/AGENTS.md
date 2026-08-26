# `ferrum2-ruleset` Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate owns remote binary RuleSet
resource lifecycle: explicit HTTPS resolution and dialing, verified local cache reads and atomic
writes, strict SRS compilation, all-or-nothing initial snapshots, and generation-preserving
refresh. Its internal dependencies are limited to `ferrum2-core`, `ferrum2-dns`, and
`ferrum2-rule`; it must not acquire runtime, configuration, or platform dependencies. Rule matching
remains in `ferrum2-rule`; configuration syntax remains in `ferrum2-config`; process-root
activation remains in the consuming composition layer.

Keep `source`, `download`, `https`, `cache`, `loader`, `snapshot`, `refresh`, and `error` as the real
owner seams. The crate root remains a curated façade; do not reintroduce a monolithic loader or
runtime re-export layer.

Do not add a local-source configuration mode. A local file in this crate is only a verified cache
entry bound to its remote URL, digest, metadata schema, capabilities, and generation. Preserve the
same resolver mode, immutable detour, and one absolute deadline through HTTPS redirects. A
configured-resolver failure must never fall back to system DNS.

Every download body, TLS/HTTP connection, temporary file, and blocking cache/compiler task must be
cancelled or joined. Initial materialization exposes no partial snapshot. Refresh publishes one
complete compatible generation atomically; failures retain the old generation. Errors and
observers remain closed and must not expose tags, URLs, hosts, cache paths, peers, or source errors.
`MaterializedRuleSets` is the only initial-to-refresh handoff: it binds the registry, declaration
IDs, and source identities once, shares the same registry resource with configuration, and is then
consumed to create refresh. Do not split those identities back into parallel caller-owned vectors.
HTTPS contract tests use the shared synthetic credentials in `tests/fixtures/dns-tls`; preserve
their hashes, `resolver.test` identity, provenance, and test-only trust status.

Use:

```text
cargo test -p ferrum2-ruleset --locked
cargo test -p ferrum2-ruleset --test ruleset_loader --locked
cargo test -p ferrum2-ruleset --test ruleset_https --locked
```
