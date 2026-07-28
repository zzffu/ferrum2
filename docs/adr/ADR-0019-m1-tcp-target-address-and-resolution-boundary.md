# ADR-0019: M1 TCP target address and resolution boundary

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M1；`SPEC-0002`；`TEST-0002`；
  M1-T02、M1-T03；扩展 ADR-0003、ADR-0004、ADR-0005、ADR-0010

## Context and decision boundary

`ferrum2-core::TargetAddr` 已表达 IP/domain，但 current domain owner 只检查长度；
SOCKS5、SIP022、runtime dialer、`LocalEndpoint` 和 success reply 仍拒绝或固定
IPv4。M1 要求 IPv4、IPv6 和 domain TCP target 贯穿完整路径，同时仍明确排除
DNS proxy/resolver 产品、routing 和 configured listener/SS-server endpoint
扩展。

本 ADR 冻结 target byte policy、system resolution、deadline/candidate bounds、
error/reply family 和 authentication-before-side-effect ordering。

## Outcome invariants

- M1 扩展 application target；configured SOCKS/SS listeners 和 client 的
  configured Shadowsocks server endpoint 可继续只支持 IPv4。
- SOCKS5 与 SIP022 的 IPv4/IPv6/domain wire encoding 严格遵循各自规范；
  normalized target 保留 address family 和原始 domain bytes。
- domain 必须是 1～255 bytes、ASCII、port 非零；不做 IDNA、Unicode、
  case folding、trailing-dot 或 DNS label normalization。
- malformed/unsupported address、non-ASCII、empty/oversized domain 和 zero port
  必须在 resolution、dial、replay insertion、forwarding 或 accepted-state
  mutation 前失败。
- domain 只用 host/runtime system resolver；不新增 cache、proxy、custom DNS
  protocol、search-domain policy、routing 或 management surface。
- resolution 与全部 candidate connect attempts 共享一个既有 configured absolute
  connect deadline；不能为每个阶段或 candidate 重置时钟。
- resolver 最多消费前 16 个 candidates；不得产生 input-dependent unbounded
  collection。M1 不要求并行 Happy Eyeballs。
- `LocalEndpoint` 与 `SessionReply::succeeded` 端到端使用 `SocketAddr`；
  success reply 编码真实 IPv4/IPv6 local endpoint。
- timeout、cancellation、half-close、owner cleanup、bounded buffers 和
  destination redaction 继续遵守 M0 contract。

## Options considered

### Option A：保持 IPv4 endpoint contract，为 IPv6 合成 IPv4 reply

会虚报已建立 socket 的 local endpoint，并使 core/runtime 成为 partial family
conversion。拒绝。

### Option B：为 v4/v6 建两套 endpoint/reply traits

扩大所有 outbound 接口且没有提供额外隔离。拒绝。

### Option C：normalized target + system resolution + `SocketAddr` reply

一条地址路径覆盖三个 target classes，family 只在 wire codec 和 actual socket
处变化；DNS 仍是 direct connector 的 bounded implementation detail。接受。

## Decision

### Normalized target contract

core target 有三种结果：

- IPv4 address + nonzero port；
- IPv6 address + nonzero port；
- 原样保存的 1～255-byte ASCII domain + nonzero port。

SOCKS5 ATYP `0x01/0x04/0x03` 分别映射 IPv4/IPv6/domain；domain length 是一个
octet。SIP022 使用相同 address classes 和 normalized target owner。parser 必须
先完成 fixed/variable authenticated header、全部 address/port/padding/length
语义，再允许后续 replay mutation 或 connector call。

### Resolution and dialing

direct outbound 对 IP target 直接尝试一次。对 domain target：

1. 在 absolute connect deadline 下调用 system resolver；
2. 按 resolver 顺序至多消费 16 个 `SocketAddr`；
3. candidates 为空或 resolution failure → `HostUnreachable`；
4. 按顺序尝试 candidate，所有尝试共用同一 deadline；
5. success 返回真实 socket/local endpoint；deadline 到期立即取消剩余工作；
6. 固定 candidate sequence 下全部 dial failure 返回最后一个 concrete failure，
   并按 ADR-0003/M0 的 stable category 映射；deadline/其他仍为 general failure。

M1 不要求 candidate race、Happy Eyeballs、cache 或 family preference。实现可流式
消费而非收集，只要 16 上限、顺序、同一 deadline 和 cleanup 可观察地一致。

### Replies and failure behavior

- SOCKS success reply 的 BND.ADDR/BND.PORT 来自 actual outbound local endpoint。
  IPv4 继续 ATYP `0x01` 且 M0 bytes 不变；IPv6 使用 ATYP `0x04` 和 16-byte
  address。
- pre-success `NetworkUnreachable/HostUnreachable/ConnectionRefused/other`
  继续映射 `0x03/0x04/0x05/0x01`。
- server-side target failure 仍发生在 SOCKS success 之后，不产生第二个 SOCKS
  reply；stream 以既有 EOF/RST semantics 结束。
- domain、IP 和 resolved destination 不进入 tracing field 或 metric label；
  error 只暴露 bounded stable category。

### Lifecycle and mutation ordering

resolver future、candidate iterator、connecting sockets 与 established socket
都由当前 connection owner 管理。cancel/shutdown/deadline 必须终止它们；失败不
影响其他 flow。

server path 的顺序固定为：

```text
full authenticated SIP022 header
→ complete address/port/padding semantics
→ exact replay check-and-insert
→ bounded resolution / direct connect
→ relay
```

client SOCKS path 在完整校验 normalized target 后才连接 configured SS server；
不因 domain bytes 创建额外未拥有 task。

## Consequences and tradeoffs

- Positive：core、SOCKS5、SIP022 与 runtime 共享一个地址语义，避免 partial
  IPv6 support。
- Positive：bounded system resolution 满足 domain user value，而不引入 DNS
  产品或 process-global state。
- Negative：sequential candidates 可能比 Happy Eyeballs 慢；M1 以同一 deadline
  和确定性生命周期优先，后续优化需保持 contract。
- Negative：ASCII byte policy 不执行常见 DNS normalization；operator 必须提供
  resolver 可接受的 ASCII form。

## Compatibility, migration, and rollback

所有 M0 IPv4 target/request/reply bytes 与 error categories 保持不变。schema
version 不变；configured endpoints 不扩展。回滚时 IPv6/domain SOCKS requests
恢复 unsupported-address failure，IPv4 继续工作；没有 persisted data migration。

若后续要增加 IDNA、parallel dialing、custom resolver、DNS cache 或 configured
endpoint IPv6，属于新的 observable contract，不能作为 M1 helper 细节引入。

## Verification seam

最小主证据是一张 address-path table，跨 core → SOCKS5 → SIP022 → recording
resolver/dialer：

- IPv4、IPv6、1-byte/255-byte ASCII domain positive rows；
- empty/256-byte/non-ASCII/truncated/unsupported/zero-port negative rows；
- 负向均证明 zero resolution/dial/replay/session mutation；
- paused time 证明 resolution + 16 candidates 共享同一 absolute deadline，
  cancellation 清理未完成 work；
- actual IPv4/IPv6 `SocketAddr` success reply 与 stable failure mapping；
- local real-process 只补充 address/method cross-module interaction，不复制 codec
  table。

## References

- `docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md`
- `docs/adr/ADR-0003-m0-configuration-and-cli-contract.md`
- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/adr/ADR-0010-m0-opaque-sip022-duplex-flow.md`
- [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)
- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
