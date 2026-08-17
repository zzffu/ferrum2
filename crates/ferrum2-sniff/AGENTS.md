# ferrum2-sniff Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-sniff` classifies caller-owned, bounded bytes as DNS, TLS ClientHello, or HTTP request metadata. It does not terminate protocols, decrypt ECH, choose policy, or read from a transport. Keep `Protocol`, `Transport`, `Progress`, and `Metadata` closed and preserve caller-supplied evaluation order. `Metadata` debug output must never reveal detected domains.

Parsing is deliberately fail-closed. Bytes beyond `max_bytes` are `Invalid`, and `NeedMore` is valid only while the current length is below that limit. DNS over TCP has a two-byte frame length; incomplete port-53 frames may delay later sniffers, while incomplete non-53 frames do not. A complete valid DNS query is port-neutral. UDP DNS input is one complete datagram, never a stream fragment. TLS and HTTP are TCP-only. TLS reports only the name observable to rustls, including an outer/cover SNI; HTTP derives names from a single `Host` header or a CONNECT authority and does not accept IP literals as domains.

## Focused Verification

Run:

```text
cargo test -p ferrum2-sniff --locked
cargo test -p ferrum2-sniff --test sniff_contract --locked
```

For parser changes, extend fragmentation loops through every byte boundary, exact-limit cases, malformed-but-plausible inputs, transport strictness, composite ordering, and redaction assertions.
