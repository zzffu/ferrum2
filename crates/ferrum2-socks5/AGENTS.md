# ferrum2-socks5 Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-socks5` owns the bounded SOCKS5 no-authentication handshake, exact request/reply bytes, retained control stream, and UDP datagram codec. It does not open outbound sockets or run the UDP relay. Callers use `accept_command` for both TCP CONNECT and `SocksCommand::UdpAssociate`. Preserve the one-shot, consuming `SessionReply` API and keep UDP association success pending until the caller has completed socket setup.

Treat every wire field as hostile. Reads must remain bounded under arbitrary fragmentation, targets must have non-zero ports, and domains must satisfy `TargetAddr` validation. Error values and formatting must not retain targets, payloads, or transport errors. Replies are protocol contracts: retain their exact RFC status mapping and IPv4/IPv6 layout.

UDP decoding is allocation-free and borrows the payload. Accept only zero RSV, zero FRAG, supported ATYP values, ASCII non-empty domains, and complete datagrams no larger than `MAX_SOCKS_UDP_DATAGRAM_BYTES` (65,507 bytes). RFC 1928 fragmentation is intentionally unsupported. Encoding uses caller-owned storage; bounds failures must leave a too-short output unchanged.

## Focused Verification

Run:

```text
cargo test -p ferrum2-socks5 --locked
cargo test -p ferrum2-socks5 --test command --locked
cargo test -p ferrum2-socks5 --test udp --locked
```

Add exact-wire, every-truncation, maximum-size, one-shot reply, and retained-control tests when changing the corresponding contracts.
