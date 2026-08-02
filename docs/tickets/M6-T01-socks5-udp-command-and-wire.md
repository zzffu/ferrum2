---
id: M6-T01
milestone: M6
status: done
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

- [x] Existing greeting、CONNECT、reply and negative bytes remain exact；the existing core
      `Inbound` interface remains CONNECT-only and `BIND` remains unsupported。
- [x] The command interface retains the control stream and one-shot reply owner, parses a
      bounded RFC address plus zero/nonzero source port, and lets composition reply only
      after socket setup。
- [x] Exact failures are fixed：disabled/`BIND` `REP=07`、unsupported `ATYP` `REP=08`、
      complete invalid/setup `REP=01`、incomplete request no reply；a failed reply write
      rolls back and never attempts a second reply。
- [x] UDP decode/encode supports IPv4/IPv6/ASCII-domain targets and exact payload while
      rejecting truncation、RSV、FRAG、ATYP、domain and zero-port failures before allocation。
- [x] Fragmentation errors are distinguishable only as a closed category so the caller can
      silently drop；Debug/Display expose no address or payload。
- [x] Exact T01 commands, Quick, ticket budget and blocking Architect/QA review pass。

## Validation

Run `TEST-0007` T01 commands, then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: ticket `027d897bcc81212ea79ee5f74a17d86bf78597cc` plus repair
  `53b603012a766ea5160b15421f6e943a5fa8fb51`；integrated as
  `6cacf43` plus exact accepted SHA `7534912c7aed84d5ce4efd09b8532305dc3923e4`。
- Review: Architect `PASS`；QA `PASS` after `M6T01-QA-001/002` were closed by the
  tests-only repair；no finding remains open。
- Notes: Exact T01、Quick and post-integration commands passed；workspace tests reported
  `260 passed / 0 failed / 2 ignored`。Ticket budget returned `PASS_ADVANCE` with
  code/tests `14288/20951` and anchor debt `-42`。

## Rollback / risk

One crate-local revert restores the old CONNECT-only behavior。Do not move socket/config policy
into the protocol module or share Shadowsocks address helpers across protocol crates。
