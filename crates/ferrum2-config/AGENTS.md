# `ferrum2-config` Contributor Guide

This file supplements the repository-level `AGENTS.md` for changes under this crate.

## Responsibility and Boundaries

This crate reads bounded TOML and compiles it into fully validated client/server models, routing and selector programs, DNS policy, and TUN resource plans. Keep `load_client` and `load_server` free of runtime side effects: they may read the named file, but must not bind sockets, spawn tasks, or retain source text. `raw.rs` owns Serde shapes and defaults, `validation.rs` and `validation/v2.rs` own cross-field and version rules, and `model.rs` exposes only validated state. Runtime behavior belongs in the consuming crates.

## Verification

Run:

```text
cargo test -p ferrum2-config --locked
cargo test -p ferrum2-config --test config_contract --locked
```

The contract test intentionally reads `tests/fixtures/config`. Preserve the schema-v1 compatibility cohort when extending schema v2, and add valid and field-specific invalid cases for new syntax or bounds.

## Security and Compatibility Contracts

Keep the 1 MiB pre-parse limit, UTF-8/TOML rejection, `deny_unknown_fields`, closed `ConfigErrorKind`/`ConfigField` reporting, and fail-closed graph compilation. Never include parser sources, configuration values, endpoints, tags, or keys in errors. Configuration source and decoded/canonical PSK buffers must remain zeroizing; public secret owners and route actions remain redacted. Preserve checks for profile-specific key widths, listener aliasing, loopback-only metrics, authenticated DoT/DoH names and paths, and bounded TUN memory/capture relationships.
