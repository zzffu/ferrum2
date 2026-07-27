# ADR-0004: M0 SIP022 AES-128 TCP 安全状态机

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T02、M0-T03、M0-T07；关闭 DEC-005
- **Partial supersession:** ADR-0008 仅取代下文 AES-GCM primitive KAT 的
  CAVP/NIST-authored 来源与 rights 归属；numeric cases、corrupted-tag reject 及
  本 ADR 其他决定保持有效

## Context and problem

M0 必须独立实现 SIP022 的 AES-128 TCP wire behavior，并在认证、bounds、
replay、detection prevention、response binding 和 target-connect ordering 上
fail closed。固定规范没有完整 protocol KAT，也没有替 ferrum2 选择 replay
capacity 或跨平台失败外观，因此这些行为必须在实现前冻结。

## Decision drivers and invariants

- 规范性 contract 是 ADR-0001 固定的 SIP022 revision，reference behavior 不能
  覆盖它。
- authentication 与完整 header semantic validation 必须先于 replay insertion、
  target connect、forwarding 或 accepted-session mutation。
- peer-controlled length 不得驱动未校验或无界 allocation。
- timestamp skew 超过 30 秒拒绝；incoming TCP salt exact retain 至少 60 秒。
- salt + initial fixed header 必须恰好一次底层 read；每端首个完整 header 必须恰好
  一次底层 write。
- 所有 authentication/semantic failure 使用一致 close behavior，仅终止当前 flow。

## Options considered

### Option A：显式 typed state machine + fixed-capacity buffers + exact replay set

状态转换只暴露 authenticated data；I/O call seam、clock、replay 和 connector
均可记录并断言 ordering。

### Option B：把 framing 隐藏在通用 `AsyncReadExt::read_exact/write_all`

代码短，但 helper 可以触发多次底层 I/O，不能证明 SIP022 detection-prevention
contract。

### Option C：以 reference implementation 为 protocol oracle

有助兼容性研究，但 reference 可能在 replay ordering、logging、unsafe 或 binding
比较上偏离固定规范，不能替代独立实现和 byte fixture。

## Decision

### Cryptographic wire constants

- method：`2022-blake3-aes-128-gcm`。
- PSK：16 bytes；request/response salt：16 bytes；AES-GCM tag：16 bytes。
- subkey：
  `BLAKE3-DERIVE("shadowsocks 2022 session subkey", PSK || salt)[0..16]`。
- nonce：12-byte zero-initialized little-endian counter；empty AAD；每个 chunk
  operation 后 checked increment。
- request fixed plaintext：
  `type(0):u8 || timestamp:u64be || variable_len:u16be`，11 bytes；
  request first-read wire 为 `salt 16 + ciphertext/tag 27 = 43` bytes。
- response fixed plaintext：
  `type(1):u8 || timestamp:u64be || request_salt:16 || first_payload_len:u16be`，
  27 bytes；response first-read wire 为 `salt 16 + ciphertext/tag 43 = 59`
  bytes。
- subsequent length chunk plaintext 是 `u16be`；payload plaintext 最大
  `65535` bytes。ferrum2 encoder 每个 application chunk 至多 `16384` bytes，
  decoder 必须接受 reference 合法的 `0..=65535`。

### Client request path

1. 完成 SOCKS5 no-auth IPv4 CONNECT parse，得到 normalized target。
2. 在 connect timeout 内连接 configured ferrum2/reference server。
3. 生成 request salt、wall timestamp 和 `1..=900` 的随机 nonzero padding。
4. M0 ferrum2 client 的首 header 不带 initial payload；variable header 为
   `IPv4 ATYP/address/port || padding_len || padding`。
5. 将 salt、encrypted fixed header、encrypted variable header 缓冲在一个
   contiguous buffer；调用一次底层 `write`，且返回长度必须等于整个 buffer。
   short write 是 detection failure，不调用 `write_all` 补齐。
6. 该 open 成功后才向 SOCKS peer 发送 success，然后进入双向 relay。

server 必须接受 reference client 的合法 initial payload：request variable header
在 address 后包含 `padding_len(0..=900)`、padding 和剩余 initial payload；
padding 与 initial payload 不得同时为空。

### Server validation 与 replay linearization

server 的顺序固定为：

1. 用单个底层 read operation 请求精确 43-byte request first-read 区；short read
   进入 detection failure。
2. KDF/AEAD authenticate fixed header；验证 type `0`、timestamp
   `abs_diff <= 30` 和 authenticated `u16` length。
3. 只使用与 peer 值无关的 fixed maximum wire buffer（最大 `65535 + 16`）读取并
   authenticate variable chunk；不按声明值做无界/peer-sized reserve。
4. 验证完整消费、ATYP/address/port、padding `<=900`、M0 IPv4 support，以及
   `padding > 0 || initial_payload 非空`。
5. 在一个 critical section 中 purge expired salts，并原子执行 exact
   check-and-insert。到此之前任何失败都不得 mutation replay/accepted state。
6. 只有插入成功才产生 accepted `Session`，然后调用 direct target connector；
   authenticated initial payload 只在 target connect 成功后 forward。

replay store 使用 exact `HashMap<Salt16, MonotonicExpiry>` 加 insertion-order
`VecDeque`，由一个 mutex 保护：

- TTL 为 60 秒；`59.999s` 仍存在，elapsed `>=60s` 才可 purge。
- 默认 capacity `65536`，validated range `1024..=1048576`。
- capacity 满且没有已过期 entry 时拒绝新 flow 为 `ReplayCapacity`；不得 eviction
  未满 60 秒的 live entry，也不得使用 Bloom/filter/LRU。
- 同一 salt 的并发合法请求恰好一个插入成功。
- malformed/authentication/semantic failure 不插入；合法请求插入后即使 target
  connect 失败也保留至 TTL。
- store 是 in-memory；进程重启会丢失它。M0 不引入 persistence，剩余重启风险由
  30 秒 timestamp window 缩小但不宣称消除。

### Response 与 binding

- target connect 成功没有 SIP022 acknowledgement。server 等到 target 返回首个
  **非空** payload 后才生成 response salt/header；若 target 在任何 response bytes
  前关闭，server 关闭 SS flow，不发送空 response header。
- response salt 必须不同于对应 request salt。salt、encrypted fixed response
  header 和 encrypted first payload 放入一个 contiguous buffer并单次底层 write。
- client 单次读取 59-byte first-read 区，authenticate 后依次验证 type `1`、
  timestamp `abs_diff <=30`、完整 request-salt equality 和 payload length；payload
  authentication 完成前不得交给 SOCKS peer。
- wrong request salt、bad tag/type/time/length、short first I/O 均 detection failure。

### Detection-prevention close

protocol 将 initial read/write/auth/semantic failures分类为 `DetectionFailure`。
`ferrum2-shadowsocks` 对外返回可穷尽匹配的
`ShadowsocksError::Detection(DetectionReason)`；它不依赖runtime/socket2，但其IO
generic必须实现core `AbortiveClose`。进入任一approved detection failure时，state
machine恰好调用一次`mark_abortive(&mut io)`，随后无论mark成功或失败都立即进入
terminal state并返回closed error，不能read/write/reuse该transport。

runtime adapter的`mark_abortive`内部调用
`socket2::SockRef::set_linger(Some(Duration::ZERO))`，owner随后drop socket，目标是
RST。普通EOF、operator shutdown、target refusal和非detection protocol error绝不
调用该capability。不得用字符串/日志reason决定是否调用。

实现必须有一个记录“底层 read/write 调用次数和长度”的transport seam。T03测试
closed error classification与`AbortiveClose`调用次数，T06测试socket capability，
T07/T08用native probe证明end-to-end close。测试不得用
`read_exact`/`write_all` 的源码名称代替该证据。native socket probe 对逐字节、
bad tag/type/time/length 比较相同的 close class；若某目标无法稳定产生批准的 RST，
M0 gate 阻塞并修订 ADR，不能静默退化。

### KAT 与 fixture

- BLAKE3 primitive artifact固定为官方tag `1.8.5`、commit
  `93a431c78a52d7ccf0f366f106467f5070e6075e` 的
  `test_vectors/test_vectors.json`，file SHA-256
  `dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624`；
  M0选择`input_len = 0, 1, 1024`的derive-key rows。artifact继承该仓库
  `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception`，provenance必须随
  fixture提交。
> **ADR-0008 partial supersession:** 下项保留为历史记录；其中
> “NIST CAVP source”“NIST-authored/official validation vector”和 NIST public
> information rights 归属已被 ADR-0008 取代。两个 numeric cases 与 case 2
> corrupted-tag reject 不变，并由 ADR-0008 继续规范。
>
- AES-GCM primitive source固定为NIST CAVP `gcmtestvectors.zip`，SHA-256
  `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`。M0只提交并
  标注来源的两个AES-128/96-bit-IV/empty-AAD numeric cases：
  1. all-zero key/IV、empty plaintext/ciphertext、tag
     `58e2fccefa7e3061367f1d57a4e7455a`；
  2. all-zero key/IV、16-byte zero plaintext、ciphertext
     `0388dace60b6a392f328c2b971b2fe78`、tag
     `ab6e47d42cec13bdf53a67b21257bddf`。
  case 2 tag最低bit翻转是required decrypt-failure case。NIST来源按其官方public
  information/copyright notice归档并注明attribution；不提交整个zip。
- repository-owned `tests/fixtures/sip022/aes128-tcp-v1.json` 明确标为“非官方
  SIP022 KAT”。其inputs不留给Engineer选择：
  - PSK bytes `000102030405060708090a0b0c0d0e0f`；
  - request salt `101112131415161718191a1b1c1d1e1f`；
  - response salt `202122232425262728292a2b2c2d2e2f`；
  - timestamp `1700000000`、target `127.0.0.1:8080`；
  - request case A：padding `a1b2c3`、empty initial payload；
  - request case B：zero padding、initial payload ASCII `ping`；
  - response first payload ASCII `pong`并绑定上述request salt。
- 独立generator固定在`tests/fixtures/sip022/generator.rs`，只直接调用pinned
  `blake3`/`aes-gcm` primitive API并自行构造bytes；禁止import任何ferrum2
  production module。`PROVENANCE.toml`记录Rust 1.97.1、generator source SHA-256、
  output SHA-256、dependency versions/licenses和上述inputs。expected bytes不在
  test runtime重新生成；generator/output变更必须Architect与QA双review，并由四项
  reference interop交叉验证。

## Consequences and tradeoffs

### Positive

- 所有 attacker-controlled path 的副作用 ordering 可由 recording adapters 直接证明。
- exact replay 和 fixed bounds 满足规范，无 probabilistic false positive。
- M1 可以替换 method-specific cipher owner而复用 TCP framing/state transitions。

### Negative

- initial short read/write 被主动拒绝，要求 reference 的 first header 符合 SIP022
  detection-prevention behavior。
- 最大合法 reference frame 需要每个 active decrypt direction 一个约 64 KiB 的
  bounded scratch buffer。
- in-memory replay state 无法跨重启；持久化会引入新 threat/format/lifecycle，
  因而延期。

## Compatibility and upstream divergence

sing-box 与 shadowsocks-rust 只作为黑盒 compatibility gate。已知上游可能在 replay
ordering、request-salt comparison、salt tracing 或 `unsafe` 使用上与本 ADR 不同；
ferrum2 不复制这些实现选择。合法 wire divergence 只能通过修订固定规范/ADR 处理。

## Migration and rollback

M0 没有旧 wire state。回滚是关闭 listener 并回退 integrated commit；无持久 replay
格式。M1 新 cipher 必须复用 message/state/replay contract，method-specific constant
由新 spec additive 增加。

## Verification plan

- M0-CRYPTO-001～004：primitive/KDF/nonce vectors与secret/entropy。
- M0-PROTO-001～006：bounds、auth、timestamp、side-effect ordering、allocation与
  composite request/response wire fixture。
- M0-REPLAY-001～004：exactness、concurrency、TTL/rollback、capacity。
- M0-DETECT-001～003：底层I/O/mark call-count、runtime socket capability与native
  close probe。
- M0-BIND-001：response request-salt binding。
- M0-INT-001～004：两个 reference、两个方向。

## References

- `AGENTS.md`
- `docs/research/M0-upstream-baseline.md`
- `docs/adr/ADR-0008-m0-aes-gcm-kat-provenance-correction.md`
- [固定 SIP022 文件](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [SIP022 live page](https://shadowsocks.org/doc/sip022.html)
- [BLAKE3 1.8.5 vectors](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/test_vectors/test_vectors.json)
- [Historical CAVP artifact whose mismatch is corrected by ADR-0008](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES)
- [Historical NIST notice superseded as rights attribution by ADR-0008](https://www.nist.gov/copyrights-disclaimers)
