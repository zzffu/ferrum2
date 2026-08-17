# ferrum2-observability Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate is the closed telemetry boundary: `src/lib.rs` defines approved trace enums and fields, builds caller-owned JSON subscribers, owns isolated Prometheus registries, and emits deterministic OpenMetrics text. It does not install global tracing state, start listeners, or spawn tasks; endpoint serving and process composition belong elsewhere.

Keep trace and metric dimensions closed and low-cardinality. Never add free-form messages, error sources, configuration text, keys, salts, nonces, wire/session identities, peers, destinations, targets, or sniffed identity data. Add a typed enum variant when a new category is necessary, and update the exact metadata whitelist with its contract tests. Preserve existing metric family names, types, and label meanings; additions are allowed, but insertion order must not affect encoded output. `Metrics` exposes manual lifecycle gauges, so callers remain responsible for balanced increments, decrements, and final values.

Use these focused gates:

```text
cargo test -p ferrum2-observability --locked
cargo test -p ferrum2-observability --test tracing_contract --locked
cargo test -p ferrum2-observability --test metrics_contract --locked
```

Extend sentinel-based redaction coverage whenever the public telemetry surface changes. For authenticated sniffing, preserve the single closed metric-and-trace tuple per attempt and the absence of any identity channel.
