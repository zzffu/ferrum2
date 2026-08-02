---
id: M6-T01
milestone: M6
status: ready
depends_on: []
owns:
  - crates/ferrum2-socks5/src/lib.rs
  - crates/ferrum2-socks5/tests/**
---

# M6-T01 — Add SOCKS5 UDP command and wire interface

## Outcome

Expose one deep SOCKS5 command interface that preserves CONNECT while returning a validated,
reply-pending `UDP ASSOCIATE`, plus bounded standalone UDP header decode/encode with no socket
or runtime policy。

## Acceptance

- [ ] Existing greeting、CONNECT、reply and negative bytes remain exact；the existing core
      `Inbound` interface remains CONNECT-only and `BIND` remains unsupported。
- [ ] The command interface retains the control stream and one-shot reply owner, parses a
      bounded RFC address plus zero/nonzero source port, and lets composition reply only
      after socket setup。
- [ ] UDP decode/encode supports IPv4/IPv6/ASCII-domain targets and exact payload while
      rejecting truncation、RSV、FRAG、ATYP、domain and zero-port failures before allocation。
- [ ] Fragmentation errors are distinguishable only as a closed category so the caller can
      silently drop；Debug/Display expose no address or payload。
- [ ] Exact T01 commands, Quick, ticket budget and blocking Architect/QA review pass。

## Validation

Run `TEST-0007` T01 commands, then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

One crate-local revert restores the old CONNECT-only behavior。Do not move socket/config policy
into the protocol module or share Shadowsocks address helpers across protocol crates。
