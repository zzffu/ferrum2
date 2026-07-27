+++
id = "M0-T05"
title = "Implement the SOCKS5 no-auth IPv4 CONNECT inbound"
milestone = "M0"
status = "in_progress"
priority = "P1"
blocked_by = ["M0-T01"]
owns = [
  "crates/ferrum2-socks5/src/**",
  "crates/ferrum2-socks5/tests/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-SOCKS-001 proves version-5 no-auth negotiation, IPv4 CONNECT parsing, normalized Session ownership, and success bytes 05 00 00 01 plus the established client-to-Shadowsocks socket local IPv4 address and big-endian port",
  "M0-SOCKS-002 passes for no acceptable auth, malformed or short input, BIND, UDP ASSOCIATE, domain, IPv6, and port-zero behavior; every emitted request-stage failure uses ATYP 01, BND.ADDR 0.0.0.0, and BND.PORT 0",
  "The M0-ENDPOINT-001 general_failure case writes exactly 05 01 00 01 00000000 0000 once",
  "SocksReplyPending consumes self on success or failure, so it sends at most one reply and maps only pre-Shadowsocks-open connect errors according to SPEC-0001",
  "The crate contains no DNS, routing, Shadowsocks, Tokio runtime-global, or binary CLI policy",
]
+++

# M0-T05: Implement the SOCKS5 no-auth IPv4 CONNECT inbound

## Outcome

将application-facing SOCKS5 TCP input规范化为core `Session`，并以一次性reply owner
表达M0的乐观success/failure语义；不加入domain resolution或UDP。

## Context

本票与crypto/config/runtime并行。T07将其与Shadowsocks outbound组合并完成真实
process E2E。

## In scope

- bounded greeting/request parser和no-auth selection。
- command/ATYP validation、IPv4 `TargetAddr`构造。
- `Socks5Inbound`、`SocksReplyPending`和RFC1928 reply bytes/error mapping。
- short/malformed/unsupported input tests与fragmented I/O tests。

## Out of scope

- BIND、UDP ASSOCIATE、domain、IPv6成功路径、DNS。
- Shadowsocks connect、server target result acknowledgement。
- listener/supervisor/timeout ownership（T06/T07）。
- manifest/core修改。

## Implementation notes and constraints

- parser只按协议固定上限分配；不记录target/raw request。
- greeting无`0x00`时发`0x05 0xff`；unsupported command `0x07`；
  unsupported ATYP `0x08`。
- success reply 为 `05 00 00 01 <local-ipv4> <local-port-big-endian>`，其中
  local endpoint来自已建立的client→Shadowsocks-server socket。取得endpoint失败
  或结果非IPv4时关闭该socket，并发送general failure。
- 每个已发送的request-stage failure reply为
  `05 <REP> 00 01 00 00 00 00 00 00`；malformed version/length仍直接关闭。
- success/failure reply owner必须线性消费，不能重复reply。
- server后续target refusal不经过本crate映射第二次reply。

## Validation commands

```bash
cargo test -p ferrum2-socks5 --locked
cargo test -p ferrum2-socks5 --test negative --locked
cargo test -p ferrum2-socks5 --test negative --locked general_failure
cargo clippy -p ferrum2-socks5 --all-targets --all-features --locked -- -D warnings
cargo fmt -p ferrum2-socks5 -- --check
```

## Risks

- success时机若错误绑定server target connect，会要求SIP022不存在的ack。
- fragmented/malformed input可能造成hang或输入驱动allocation。
- reply owner若可重复使用会产生协议混淆。

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Architect verdict:
- QA verdict:
- Integrated commit:
