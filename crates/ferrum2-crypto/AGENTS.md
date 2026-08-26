# `ferrum2-crypto` Contributor Guide

This file supplements the repository-level `AGENTS.md` for changes under this crate.

## Responsibility and Boundaries

This crate owns SIP022 method profiles, exact-width secret and salt types, scoped key-provider capabilities, subkey derivation, TCP AEAD owners, nonce and entropy seams, and the cryptographic portion of UDP envelopes. `method`, `clock`, and `random` own their typed capabilities; `udp/{session,aead}` owns session identity and packet cryptography; `tcp/{key,nonce,aead}` keeps subkey derivation beside `TcpSubkey` and owns exhaustion-safe stream state. Semantic packet layout and TCP framing remain in `ferrum2-shadowsocks`; configuration decoding remains in `ferrum2-config`. Keep primitive access behind typed, method-bound owners rather than exporting raw PSK or subkey bytes.

## Verification

Run:

```text
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-crypto --test primitive_vectors --locked
cargo test -p ferrum2-crypto --test sip022_vectors --locked
cargo test -p ferrum2-crypto --test secret_entropy --locked
```

Vector tests consume `tests/fixtures/crypto`. Any vector change must retain the hashes, pinned upstream revision, generator contract, licensing, and interpretation recorded in `PROVENANCE.toml`; never replace reviewed vectors with output from the production implementation.

## Security and Compatibility Contracts

Secret owners must remain non-cloneable, redacted, explicitly clearable where exposed, and zeroized on drop. Preserve profile-specific 16/32-byte widths, zero-based u96 little-endian TCP nonces, authenticated-open behavior, and state commits only after successful operations. Nonce or packet-ID exhaustion must fail closed without mutating buffers or counters. `SecureRandom` failures have no fallback; response salts and UDP session IDs use bounded full-width collision retries. Do not expose keys, salts, nonces, identities, primitive source errors, or unauthenticated plaintext through diagnostics or partial results.
