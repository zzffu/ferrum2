# ferrum2-shadowsocks Contributor Guide

The repository-level `AGENTS.md` remains in force. This crate implements the SIP022 TCP flow state machine and socket-free bounded UDP packet/security state. It consumes key, clock, randomness, transport, and connector capabilities; raw key derivation belongs in `ferrum2-crypto`, while socket/task capacity and shutdown ownership belong in `ferrum2-runtime`.

Preserve authentication and mutation ordering. Initial TCP envelopes must authenticate and pass semantic checks before replay insertion, connection side effects, or plaintext release. Replay retention uses monotonic time, duplicate commits must have one atomic winner, and a full store fails closed without evicting live entries. Response binding covers the complete request salt. Once installed, a flow terminal is immutable; detection failures remain abortive, while later protocol and transport failures retain their closed classification. Public errors and observers must never retain or format underlying I/O errors, keys, salts, nonces, packet/session IDs, or wire bytes.

For UDP, keep `prepare_*` mutation-free: runtime capacity is reserved before the move-only commit token advances replay, association, activity, or generation state. Reject stale response capabilities, preserve current/old association retention, and keep packet/frame, padding, and reusable scratch bounds exact.

Use these focused gates:

```text
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-shadowsocks --test detection_prevention --locked
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked
cargo test -p ferrum2-shadowsocks --test udp_packets --locked
```

Update reviewed wire-vector, fragmentation, tamper, concurrency, and allocation-bound tests whenever their corresponding contract changes.
