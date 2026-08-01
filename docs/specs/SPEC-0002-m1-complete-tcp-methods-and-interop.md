# SPEC-0002: M1 完整三方法 TCP 与 12 项互操作

- **Status:** Approved
- **Milestone:** M1
- **Related ADRs:** `ADR-0018`、`ADR-0019`；继续适用 `ADR-0002`～`ADR-0006`、
  `ADR-0009`、`ADR-0010`、`ADR-0012`、`ADR-0014`、`ADR-0016`、`ADR-0017`
- **Test plan:** `docs/test-plans/TEST-0002-m1-complete-tcp-methods-and-interop.md`
- **Tickets:** M1-T01、M1-T02、M1-T03、M1-T04

## Objective and non-goals

把 M0 已关闭的 AES-128 IPv4 TCP 纵切扩展为：

```text
SOCKS5 no-auth CONNECT: IPv4 | IPv6 | ASCII domain
  → ferrum2-client
  → one shared SIP022 TCP flow:
       AES-128-GCM | AES-256-GCM | ChaCha20-Poly1305
  → ferrum2-server
  → bounded direct TCP connect
  → target
```

并在一个 exact integrated SHA 上，以 pinned sing-box 和 shadowsocks-rust 完成
`3 methods × 2 references × 2 directions = 12` 个 required TCP cases。

非目标：

- UDP、SOCKS5 `UDP ASSOCIATE` 或 public UDP inbound；
- reduced-round ChaCha、XChaCha、method negotiation/fallback；
- SIP023、多用户、多 PSK product behavior；
- routing、DNS proxy/custom resolver/cache、multiple upstreams、chaining、
  management API、hot reload；
- configured listener 或 configured Shadowsocks server endpoint 的 IPv6/domain；
- M3 最终 native packaging/lifecycle qualification；
- M4 可复现 throughput baseline 或 10,000-idle gate；
- push、PR、rerun、tag、release 或 artifact publication；hosted run 另需授权。

## User/operator-visible behavior

### Configuration and methods

- 两个 binary 的 schema v1 接受且只接受：
  `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、
  `2022-blake3-chacha20-poly1305`。
- Standard Base64 必须 canonical；decoded PSK 对 AES-128 恰为 16 bytes，对
  AES-256/ChaCha 恰为 32 bytes。
- wrong method/key pair、别名、未知/reduced-round method、malformed/noncanonical
  secret 以既有 exit 2/redacted semantic error 在 listener/runtime/connector/
  tracing resource 创建前失败。
- `--check-config` success/output、exit 0/1/2、unknown-field 和 size/range policy
  继续遵守 ADR-0003。method 是固定三值，可在需要时作为 bounded diagnostic；
  key/salt/nonce/target/domain 不可观察。

### SOCKS5 targets and replies

- greeting/no-auth/CONNECT behavior 不变；`BIND`/`UDP ASSOCIATE` 仍 unsupported。
- CONNECT 支持 IPv4 ATYP `0x01`、domain `0x03`、IPv6 `0x04`。
- domain 是 1～255-byte ASCII；port 必须非零。不执行 IDNA、Unicode、case、
  trailing-dot 或 label normalization。
- malformed/truncated/unsupported/non-ASCII/oversized/zero-port request 只终止该
  flow，且先于 resolution、dial、replay/session mutation。
- pre-success failure reply 继续按
  `network unreachable→0x03`、`host unreachable→0x04`、
  `connection refused→0x05`、timeout/other→`0x01`。
- success reply 报告 actual client→Shadowsocks-server socket local endpoint：
  IPv4 使用 ATYP `0x01`；若 endpoint 是 IPv6，使用 ATYP `0x04`。现有 IPv4
  bytes 不变。
- server target failure 仍在 SOCKS success 之后表现为 stream EOF/RST，不发送
  第二个 SOCKS reply。

### Domain resolution and direct outbound

- IP target 直接连接；domain target 使用 host/runtime system resolver。
- 最多消费 resolver 前 16 个 candidates，保持顺序；resolution 与所有 sequential
  connect attempts 共用 configured absolute connect deadline。
- resolution failure/no candidate 映射 HostUnreachable；固定 candidate sequence
  的全部 dial failure 使用最后 concrete error 的既有 stable mapping；deadline
  为 GeneralFailure。
- cancellation/deadline/shutdown 终止 resolver、candidate sockets 和 flow-owned
  task；不留下 cache/process-global resolver state。

### TCP security and wire behavior

- 三个 method 使用 `ADR-0018` 的 exact 16/32-byte PSK/salt/subkey profile、
  16-byte tags、12-byte little-endian counter nonce 与 method-derived first-read。
- method 在 config/flow construction 时固定；peer input 无法选择、降级或重试。
- 一个 opaque flow 继续拥有 initial request/response、frame、binding、replay、
  detection-prevention、duplex 和 terminal state。
- timestamp 超过 system time ±30 seconds 拒绝；server exact salt replay set
  至少保留 60 seconds，满载 fail closed，不使用 false-positive structure。
- full authentication、message/address/padding/length semantics 全部先于 exact replay
  insertion、target connection、peer-sized allocation、forwarding 或 accepted
  state mutation。
- response header 使用 request salt 的完整 method width binding；wrong method/key、
  corrupted tag、binding mismatch、truncation、nonce exhaustion 和 semantic error
  都是当前 flow 的 abortive detection failure。

### Lifecycle and observability

- ADR-0005/0010/0012 的 bounded buffers、backpressure、direction-separated partial
  byte accounting、half-close、single fatal arbitration、phase deadlines、
  cancellation 和 graceful shutdown 对三个 method/target classes 一致。
- 不因 method/address matrix 创建 unbounded queue、input-sized allocation 或
  orphan task；flow failure 不影响其他 flow。
- 既有 tracing event/metric names、fixed labels 与 cardinality 继续兼容。
  destination/domain 不是 label，secret material 不进入 log/error/panic/trace。

### Interoperability and release evidence

- reference pins、asset hashes、license/black-box policy 继续由
  `tests/interop/versions.toml` 与 ADR-0006 管理。
- `M1-INT-001`～`M1-INT-012` 冻结唯一的
  case_id→transport/method/reference/direction mapping；exact mapping 在 TEST-0002
  冻结。providers ready 时每案恰执行一次；各案彼此独立，执行顺序和 summary
  行顺序不是合同，runner 的确定性顺序只是实现细节。这不改变单 flow 内协议规定的
  framing、nonce、handshake、payload 与 lifecycle/ordered EOF 顺序。
- 每案验证 distinct bidirectional payload bytes 和 ADR-0014 approved ordered
  clean-EOF convergence；ferrum-owned local tests 独立证明更强 post-FIN lifecycle。
- reference setup failure 使该 reference 的六案以同一 canonical root FAIL，同时
  另一 reference 可运行六案仍继续；case/cleanup timeout/panic/failure 也不得
  阻止其他 runnable cases。
- 只有同一 exact SHA、同一 GitHub run/attempt 的 12/12 PASS、cleanup complete、
  quality/MSRV/三平台全部 success 才是 M1 release PASS。missing/skipped/
  cancelled/neutral/11-of-12/provider unavailable 均非 PASS。
- local quick/full 只 compile/lint Cargo-managed qualification entry，绝不运行、
  下载或启动 external reference。

## Existing execution path and ownership

M0 product baseline 是
`8318ef106d6cd4e029bd3b02aa64125fabdda462`；run `30331336772` attempt 1
证明 AES-128 的 quality、MSRV、三平台 smoke 和 4-cell interop。该证据是 M1
entry/regression baseline，不是 M1 completion evidence。

当前代码：

- `ferrum2-config` 只接受 AES-128/16-byte PSK；
- composition roots 丢弃 parsed method；
- `ferrum2-crypto` 使用 fixed 16-byte/AES-128 owners；
- `ferrum2-shadowsocks` hard-code AES-128 factories、43/59 reads 与 IPv4 ATYP；
- `ferrum2-socks5`、`ferrum2-runtime`、`LocalEndpoint`/reply 是 IPv4-only；
- hosted qualification 只有四个 AES-128 cases。

所有 product 修改由四张 ownership-disjoint tickets 单写：

```text
M1-T01
├─ M1-T02 ── M1-T03 ──(integration blocker)── M1-T04
└─ M1-T04 implementation
```

唯一 initial frontier 是 M1-T01。T01 完成后 T02 与 T04 implementation 可并行；
T03 等待 T02；T04 最后集成并进入另行授权的 hosted qualification。

## Required contract

### Interfaces, data, and state

- method-aware secret/profile 是 crypto deep module；protocol 得到 method-derived
  wire widths 和 small seal/open capability，不得到 raw key。
- normalized target 跨 core/SOCKS5/SIP022/runtime 保留 IPv4/IPv6/domain；
  `LocalEndpoint` 与 reply 使用 `SocketAddr`。
- replay keys、request/response binding 和 salt owners 使用完整 method width。
- current key-selector future seam 保留，但 M1 不改变 single-PSK lookup semantics。

### Validation and errors

- config、SOCKS5、SIP022、resolver/dialer 的错误使用既有 bounded stable category，
  不回显 secret/target。
- 所有 peer-controlled length 在 allocation/copy 前检查；domain 和 candidate
  count 有 255/16 的显式上限。
- authentication failure 不 fallback，validation failure 不产生外部副作用。

### Security, concurrency, and lifecycle invariants

ADR-0002/0004/0005/0009/0010/0012 的 MUST invariants 全部继承。任何等价 test seam
替换须遵守 ADR-0016：执行前 mapping、相同 failure mode/independence/bounds、
exact candidate SHA 和 Architect/QA review。

### Compatibility, migration, and rollback

AES-128/IPv4 wire、config 和 M0 tests 必须 byte-compatible。没有 persisted schema
migration。回滚到 M0 binary 时，新 method configs 和 non-IPv4 targets fail closed；
AES-128/IPv4 继续运行。

## Observability

M1 不新增 operator-facing metric。若为固定三方法增加 method field/label，只能使用
三值 enum 并更新既有 cardinality policy；address/domain/PSK/salt/nonce 禁止成为
field/label。错误、capture 和 hosted summary 只包含 stable case/method/reference/
direction/status/canonical root，不含 config secret 或 destination。

## Acceptance criteria

1. **M1-AC-01:** 只接受三个 canonical methods；16/32-byte PSK/profile 匹配且所有
   cross-pair/noncanonical errors 脱敏、先于 resource creation。
2. **M1-AC-02:** 三个 methods 的 provenance-reviewed KDF/AEAD fixture、exact
   salt/subkey/nonce/tag behavior 与 tampered-tag rejection 通过。
3. **M1-AC-03:** 同一 TCP flow/state path 对三方法通过 framing、auth、replay、
   binding、detection、tamper、truncation、bounds 与 nonce-exhaustion contract。
4. **M1-AC-04:** IPv4、IPv6、1～255-byte ASCII domain 贯穿 SOCKS5→SIP022→direct
   connect；所有 invalid rows 在 resolution/dial/replay/session mutation 前失败。
5. **M1-AC-05:** resolution 与最多 16 个 sequential candidates 共用一个 absolute
   deadline；failure mapping、cleanup 和 actual `SocketAddr` reply 正确。
6. **M1-AC-06:** 三方法的 refusal、half-close、timeout/cancellation、partial-byte、
   task/socket cleanup、tracing/metrics/redaction 与 M0 行为一致。
7. **M1-AC-07:** exact integrated SHA 的 pinned-reference hosted qualification
   明确报告并取得 `M1-INT-001`～`012` 12/12 PASS，且缺失/失败不能静默跳过。
8. **M1-AC-08:** authoritative full、Rust 1.85 MSRV、三平台 smoke、dependency/
   license/unsafe/scope review 在同一 candidate 上通过；没有 UDP/deferred scope。

## Implementation freedom

Engineer 可选择 private enum/type/helper 名、bounded 16/32 storage representation、
流式或 small-vector candidate consumption、table-test organization 和同等强度的
existing-seam extension。不得改变 method/address/deadline/error/security/release
observable contract，不得增加 public test hook、process-global state 或新 task
runner。

## Open decisions

None. Hosted push/run authorization 是外部执行权限，不是未决产品设计。
