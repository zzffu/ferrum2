# ferrum2-shadowsocks Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate implements the SIP022 TCP flow state machine and socket-free bounded UDP packet/security state. TCP ownership is split across `error`, `observe`, `replay`, `handshake`, `flow`, and `wire`; UDP keeps replay ownership beside client/server state and shared wire validation. It consumes key, clock, randomness, transport, and connector capabilities; raw key derivation belongs in `ferrum2-crypto`, while socket/task capacity and shutdown ownership belong in caller composition. The optional `tokio` module is the single executor adapter for `TransportIo`, `PlainDuplex`, and `Connector`; it must not acquire sockets, spawn tasks, or own listener and signal policy.

Preserve authentication and mutation ordering. Initial TCP envelopes must authenticate and pass semantic checks before replay insertion, connection side effects, or plaintext release. Replay retention uses monotonic time, duplicate commits must have one atomic winner, and a full store fails closed without evicting live entries. Response binding covers the complete request salt. Once installed, a flow terminal is immutable; detection failures remain abortive, while later protocol and transport failures retain their closed classification. Public errors and observers must never retain or format underlying I/O errors, keys, salts, nonces, packet/session IDs, or wire bytes.

For UDP, keep `prepare_*` accepted-state mutation-free: runtime capacity is reserved before the move-only commit token advances replay, association, activity, or generation state. Encode semantic bodies directly into crypto-owned final-wire reservations. Borrowed receive copies the wire once into reusable scratch; exclusive in-place and owned receive destructively open their wire while preserving method-specific body offsets. In-place exact materialization copies only the authenticated payload and clears the reusable receive wire. Authentication or semantic failure clears candidate plaintext, and current replay checks precede payload/view release while commit still rechecks atomically. Reject stale response capabilities, preserve current/old association retention, and keep packet/frame, padding, and reusable scratch bounds exact.

Use these focused gates:

```text
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-shadowsocks --test detection_prevention --locked
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked
cargo test -p ferrum2-shadowsocks --test udp_packets --locked
cargo test -p ferrum2-shadowsocks --features tokio --test tokio_adapter --locked
```

Update reviewed wire-vector, fragmentation, tamper, concurrency, and allocation-bound tests whenever their corresponding contract changes.
