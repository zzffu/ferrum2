# M0 上游基线证据笔记

- **研究范围：** ferrum2 M0（`2022-blake3-aes-128-gcm` TCP 安全纵切）所需的规范、Rust/toolchain、crate、参考实现和目标平台事实。
- **查询日期：** 2026-07-27（Asia/Shanghai）。下文所有“当前/最新”事实均以该日为准；表格中的查询日不再逐链接重复。
- **证据规则：** 只使用官方规范、Rust 官方文档/发布物、crates.io/docs.rs、上游 release/tag/source。没有把博客转述、第三方教程或搜索摘要当作证据。
- **术语：** “来源事实”是上游直接声明或固定源码直接可见的内容；“建议”是面向 ferrum2 M0 的取舍，不能冒充规范要求。

## 结论摘要

以下均为**建议**：

1. 将 SIP022 wire contract 固定到官方站点仓库
   [`shadowsocks/shadowsocks-org@34598d65054dad975d330ff9d7317b0d41cf1efd`](https://github.com/shadowsocks/shadowsocks-org/commit/34598d65054dad975d330ff9d7317b0d41cf1efd)，并在 ADR/spec 中同时记录
   `docs/doc/sip022.md` 的 Git blob
   [`f6b203facf219fe47bfe2913c2e576240d2bf1f9`](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)。
   官方页面没有自身版本号，仓库也没有可用 release/tag；不能只引用会漂移的 live URL。
2. 开发、locked build 和 release evidence 使用当前 stable
   **Rust 1.97.1**；workspace `rust-version`/MSRV 设为 **1.85.0**，使用
   Edition 2024、resolver 3，并增加真实的 1.85.0 resolved-graph gate。
3. M0 直接依赖控制在：
   `tokio`、`bytes`、`socket2`、`serde`、`toml`、`tracing`、
   `tracing-subscriber`、`prometheus-client`、`aes-gcm`、`blake3`、
   `base64`、`zeroize`、`getrandom`、`clap`、`thiserror`。
   不直接引入 `metrics`/`metrics-exporter-prometheus`、`secrecy`、
   `subtle` 或 `rand`。
4. M0 互操作基线固定为：
   **sing-box v1.13.14 / commit `25a600d…`** 与
   **shadowsocks-rust v1.24.0 / commit `7ee1aa9…`**。只把它们当成黑盒
   reference executable；不把其协议核心链接进 ferrum2，也不复制代码或 fixture。
5. 将“Windows”收窄为 `x86_64-pc-windows-msvc`；另外两个精确 triple 为
   `x86_64-unknown-linux-gnu` 和 `x86_64-unknown-linux-musl`。三个目标都做
   `--locked` binary build；配置 smoke 必须在匹配 ABI 的 runner 上实际运行，
   不能用 `cargo check` 或一次交叉链接代替。

## A. SIP022 固定快照与 AES-128 TCP

### A1. 可固定的规范修订

| 来源事实 | 直接证据 | 查询日 |
|---|---|---|
| 正式页面是 `SIP022 AEAD-2022 Ciphers`，页面的 “Edit this page” 指向 `shadowsocks/shadowsocks-org/main/docs/doc/sip022.md`。页面没有规范版本号，`Last updated` 也没有给出值。 | [正式页面](https://shadowsocks.org/doc/sip022.html)、[当前源码路径](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md) | 2026-07-27 |
| 查询日官方站点仓库 `main` 为 `34598d65054dad975d330ff9d7317b0d41cf1efd`；该 revision 下规范文件 blob 为 `f6b203facf219fe47bfe2913c2e576240d2bf1f9`。 | [固定 commit](https://github.com/shadowsocks/shadowsocks-org/commit/34598d65054dad975d330ff9d7317b0d41cf1efd)、[固定文件](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)、[固定 raw](https://raw.githubusercontent.com/shadowsocks/shadowsocks-org/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md) | 2026-07-27 |
| 该仓库没有发布 tag；因此不能用语义版本固定 SIP022。 | [官方 tags API](https://api.github.com/repos/shadowsocks/shadowsocks-org/tags) | 2026-07-27 |
| SIP022 跟踪 issue 将 “Main spec” 指向 `Shadowsocks-NET/shadowsocks-specs`；该原始规范文件最近一次内容 commit 为 `60c3f41461a303ba3d7f8837065294699b1e0526`。这可作 provenance 辅证，但正式发布页面仍是 ferrum2 的规范性入口。 | [SIP022 issue #196](https://github.com/shadowsocks/shadowsocks-org/issues/196)、[原始规范固定 commit](https://github.com/Shadowsocks-NET/shadowsocks-specs/commit/60c3f41461a303ba3d7f8837065294699b1e0526) | 2026-07-27 |

**建议：** ADR 同时写入 repository commit、file blob 和 raw URL。不要把
“2022”当作规范版本，也不要以两个参考实现的共同行为取代固定规范。

### A2. AES-128-GCM TCP 的规范事实

本节的 wire facts 均来自上述[固定 SIP022 文件](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
（查询日 2026-07-27）。

| 主题 | 来源事实 |
|---|---|
| PSK 与 salt | `2022-blake3-aes-128-gcm` 的 PSK 是 base64 表示的**恰好 16 bytes** 随机 key；salt 也是 **16 bytes**。不得从口令调用 `EVP_BytesToKey` 或其他 password-to-key 方法。每个 request/response stream 有自己的随机 salt。 |
| KDF 输入与 context | key material 是 `PSK || salt`；BLAKE3 derive-key context 必须是精确 ASCII 字符串 `shadowsocks 2022 session subkey`。 |
| AEAD nonce | 每个 stream 使用一个 **12-byte、little-endian 整数 counter** 作为 nonce，并在每次 AEAD encrypt/decrypt 后递增。request 和 response 是不同 stream、不同 salt、不同 subkey/counter。 |
| tag | 图示给出的每个 AES-GCM chunk authentication tag 是 **16 bytes**。 |
| request stream | `16B salt` → encrypted fixed header → encrypted variable header → 重复的 encrypted length chunk / encrypted payload chunk。每个 chunk 独立认证。 |
| request fixed header | plaintext 为 `type:1B || timestamp:u64be:8B || variable-header-length:u16be:2B`，共 **11 bytes**；wire 上再加 16-byte tag，共 **27 bytes**。type 必须为 client stream `0`。 |
| request variable header | plaintext 为 `SOCKS5 ATYP/address/port || padding-length:u16be || padding || initial payload`，其总 plaintext 长度由 fixed header 的 length 指定。 |
| response fixed header | AES-128 plaintext 为 `type:1B || timestamp:u64be:8B || request-salt:16B || first-payload-length:u16be:2B`，共 **27 bytes**；wire 上再加 16-byte tag，共 **43 bytes**。type 必须为 server stream `1`。该 chunk 同时是第一个 length chunk。 |
| 后续 data chunks | length plaintext 是 `u16be`（2 bytes，再加 16-byte tag）；payload plaintext 最大 `0xFFFF`（65,535）bytes，再加 16-byte tag。旧 AEAD 的 `0x3FFF` cap 不适用。 |
| response binding | client 必须将 response fixed header 中的 16-byte request salt 与本连接 request stream 的 salt 比对。response stream 自己的 salt 不需要放入 replay pool。 |
| timestamp replay | 与系统时间相差**超过 30 秒**的 header 必须作为 replay 拒绝。 |
| salt replay | server 必须保存所有 incoming TCP salts **60 秒**。首个 header 成功解密、timestamp 合法且 salt 未重复后才建立 session/加入 salt pool。不得使用 Bloom filter 或任何可能 false-positive 的结构。 |
| padding | request variable header 必须有 initial payload 或非零随机 padding；padding 范围是 0..=900，但无 initial payload 时 0 不合法。server 必须拒绝两者皆空，以及 padding/header 越过首部 chunk 边界的请求。response header 总是与 payload 一起发送，不需要 padding。 |
| detection prevention：写 | 随机 salt 与全部 header chunks 必须先缓冲，再以底层 socket 的**一次 write call** 发出。 |
| detection prevention：读/失败 | salt 与 fixed header 必须以底层 socket 的**恰好一次 read call**处理。短读、认证失败或语义失败时，对端不能从 FIN/RST 行为推断 server 消耗了多少字节。规范列出统一 RST（`SO_LINGER=0`）或统一 FIN 后 drain 等可选策略。 |

### A3. 规范未完全展开、M0 spec 必须显式冻结的点

以下先列**来源事实**，再给**建议**：

- 来源事实：[`blake3::derive_key`](https://docs.rs/blake3/1.8.5/blake3/fn.derive_key.html)
  固定返回 32 bytes；SIP022 的伪代码只写 `session_subkey := derive_key(...)`，
  没有在 AES-128 段落中写明如何得到 16-byte AES key。
- 来源事实：固定的 shadowsocks-rust crypto dependency
  [`shadowsocks-crypto 0.6.0`](https://docs.rs/crate/shadowsocks-crypto/0.6.0/source/src/v2/tcp/mod.rs)
  使用 BLAKE3 XOF，按 `kind.key_len()` 填充 derived key；AES-128 因而取
  derive-key output 的前 16 bytes。其 TCP nonce 数组从全零开始并按 little-endian
  递增。这是 reference behavior，不是规范文字。
- 建议：M0 spec 明写
  `subkey = BLAKE3-DERIVE(context, PSK || salt)[0..16]`、
  `nonce_0 = 12 * 0x00`、empty AAD、每个成功/尝试的 chunk operation 后
  little-endian increment；用 KAT 和两套参考实现锁定。不要把这几个值留给
  crate 默认值或隐含转换。
- 来源事实：SIP022 要求 exact 60-second salt retention，但没有规定 replay set
  的 capacity、满载策略、clock rollback 行为或并发原子性。
- 建议：M0 replay ADR 定义 monotonic expiry clock、wall-clock timestamp seam、
  capacity、满载时 fail-closed/backpressure 策略，以及“认证和完整 header
  语义校验成功前不插入”的线性化点。不得用 eviction 让未满 60 秒的 salt 提前失忆。
- 来源事实：规范给出三类 detection-prevention close strategy，但没有替 ferrum2
  选择跨 Windows/Linux 的一种。
- 建议：M0 先选 `socket2::Socket::set_linger(Some(Duration::ZERO))` 的统一 RST
  路径，或另一个经批准的统一 FIN 路径；必须用逐 byte probe 在 Windows、glibc、
  musl 三个 artifact 上验证可观察行为。`socket2` 的
  [`set_linger`](https://docs.rs/socket2/0.6.5/socket2/struct.Socket.html#method.set_linger)
  不需要 `all` feature。

### A4. KAT 状态

**来源事实：**

- 固定 SIP022 文档没有 KAT/test-vector 章节；固定官方站点树中也没有 SIP022
  vector/fixture artifact。因此，截至查询日**没有发现官方 SIP022 protocol KAT**。
  这不是说 primitive 没有 vectors。
- BLAKE3 官方仓库提供覆盖 derive-key mode 的
  [test vectors（tag 1.8.5）](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/test_vectors/test_vectors.json)，
  但其 context 和输入不是 SIP022 的 `PSK || salt` fixture。
- RustCrypto `aes-gcm` 0.11.0 的
  [AES-128-GCM tests](https://docs.rs/crate/aes-gcm/0.11.0/source/tests/aes128gcm.rs)
  标明使用 NIST CAVS vectors，并另有 Wycheproof pass/fail tests；这些验证 primitive，
  不验证 SIP022 framing/KDF/counter/binding。
- M0最终选中的两个all-zero numeric cases不在固定NIST CAVP
  `gcmtestvectors.zip`
  (`f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`)
  中。它们来自McGrew/Viega GCM proposal
  [test-vector bundle](https://web.archive.org/web/20170830120738id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz)
  的test cases 1/2；archive SHA-256为
  `511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0`。
  该artifact由submitter提供并曾由NIST托管，不是CAVP或NIST-authored
  validation vectors；规范性更正见ADR-0008。

**建议：**

1. 分开维护两层 KAT：
   - primitive gate：固定 BLAKE3 derive-mode 官方 vector 与ADR-0008固定的
     McGrew/Viega GCM proposal test cases 1/2；
   - protocol gate：仓库自有、明确标注“非官方 SIP022 KAT”的 synthetic fixture。
2. protocol fixture 至少固定 PSK、request/response salt、timestamp、SOCKS5 target、
   padding、initial payload 和每个 nonce，记录：
   full 32-byte BLAKE3 output、使用的前 16 bytes、每个 plaintext/ciphertext/tag、
   request/response binding 和完整 wire bytes。
3. expected bytes 由一个与 ferrum2 production path 独立的实现生成，再分别由
   sing-box 和 shadowsocks-rust 双向互操作确认；记录 generator version、输入、
   checksum 和 license/provenance。参考实现输出不能被称为“官方 KAT”。

## B. Rust stable 与 MSRV

### B1. 来源事实

| 事实 | 直接证据 | 查询日 |
|---|---|---|
| stable channel 是 **Rust 1.97.1**，manifest date `2026-07-16`，rustc commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`。 | [Rust 官方固定日期 channel manifest](https://static.rust-lang.org/dist/2026-07-16/channel-rust-stable.toml) | 2026-07-27 |
| Cargo 的 `rust-version` 表示 package 声明支持的最低 toolchain；不满足时 Cargo 报错，resolver 也可据此选 dependency。Rust 项目只为最新 stable 提供 bug/security fixes。 | [Cargo Book：Rust version](https://doc.rust-lang.org/cargo/reference/rust-version.html) | 2026-07-27 |
| Rust 1.85.0 于 2025-02-20 发布，并首次稳定 Edition 2024 及 rust-version-aware resolver 默认行为。 | [Rust 1.85.0 官方发布说明](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/) | 2026-07-27 |
| M0 推荐 direct dependencies 中声明的最高 `rust-version` 是 1.85（`toml`、`aes-gcm`、`zeroize`、`getrandom`、`clap`）；`blake3 1.8.5` 未声明 `rust-version`，但其 manifest 使用 Edition 2024。 | 下节每个 crate 的固定 registry metadata/source | 2026-07-27 |

### B2. 建议

- `rust-toolchain.toml` 固定 `channel = "1.97.1"`、`profile = "minimal"`，
  components 为 `rustfmt`、`clippy`；三个 release target 显式列出。
- workspace 使用 `edition = "2024"`、`resolver = "3"`、
  `rust-version = "1.85"`。**1.97.1 是可复现构建 compiler，1.85.0 是支持下限，
  两者不是同一概念。**
- CI 至少有：
  1. 1.97.1 的 quick/full/target/interop gates；
  2. 1.85.0 对 locked resolved graph 和 M0 必需 features 的 `cargo check/test` gate。
- `prometheus-client` 和 `blake3` 没有 registry `rust-version` 声明，不能仅靠
  dependency metadata 宣称 MSRV pass；必须让 1.85.0 job 实际编译 lockfile。
- 若 M0 implementation 使用了 1.85 之后才稳定的 API，应提高并记录 MSRV，
  不能用 `--ignore-rust-version` 掩盖。

## C. M0 crate 基线

### C1. 推荐的最小 direct set

版本、`rust-version`、license 和 feature map 来自每行链接的 crates.io 固定版本
metadata；feature 取舍是**建议**。查询日均为 2026-07-27。

| crate（exact release） | 上游 `rust-version` / license | M0 feature 建议 | M0 直接使用理由 |
|---|---|---|---|
| [`tokio 1.53.1`](https://crates.io/api/v1/crates/tokio/1.53.1) | 1.71 / MIT | `default-features=false`; `rt-multi-thread,macros,net,io-util,sync,time,signal`（[feature map](https://docs.rs/crate/tokio/1.53.1/features)） | runtime、TCP、bounded channels、timeouts、shutdown signal。不要用 `full`。 |
| [`bytes 1.12.1`](https://crates.io/api/v1/crates/bytes/1.12.1) | 1.57 / MIT | 默认 `std`，无额外 feature（[feature map](https://docs.rs/crate/bytes/1.12.1/features)） | owned/reusable `BytesMut`；与 `aes-gcm` in-place buffer 对接。 |
| [`socket2 0.6.5`](https://crates.io/api/v1/crates/socket2/0.6.5) | 1.70 / MIT OR Apache-2.0 | 默认 features；不要开 `all`（[feature map](https://docs.rs/crate/socket2/0.6.5/features)） | detection prevention 所需 `SO_LINGER` 和显式 socket 配置。 |
| [`serde 1.0.229`](https://crates.io/api/v1/crates/serde/1.0.229) | 1.56 / MIT OR Apache-2.0 | 默认 `std` + `derive`（[feature map](https://docs.rs/crate/serde/1.0.229/features)） | typed config。secret-bearing config type 必须自定义 redacted `Debug`。 |
| [`toml 1.1.3+spec-1.1.0`](https://crates.io/api/v1/crates/toml/1.1.3%2Bspec-1.1.0) | 1.85 / MIT OR Apache-2.0 | `default-features=false`; `std,serde,parse`，不启用 `display`（[feature map](https://docs.rs/crate/toml/1.1.3%2Bspec-1.1.0/features)） | 只反序列化/验证 M0 TOML。Cargo requirement 可写 `=1.1.3`，完整 build metadata/checksum 由 `Cargo.lock` 固定。 |
| [`tracing 0.1.44`](https://crates.io/api/v1/crates/tracing/0.1.44) | 1.65.0 / MIT | `default-features=false`; `std`（[feature map](https://docs.rs/crate/tracing/0.1.44/features)） | events/spans；M0 不需要 `attributes` proc macro。 |
| [`tracing-subscriber 0.3.23`](https://crates.io/api/v1/crates/tracing-subscriber/0.3.23) | 1.65.0 / MIT | `default-features=false`; `fmt,json,env-filter`（[feature map](https://docs.rs/crate/tracing-subscriber/0.3.23/features)） | JSON structured logs 和 bounded filter；避免默认 ANSI/tracing-log 桥。 |
| [`prometheus-client 0.25.0`](https://crates.io/api/v1/crates/prometheus-client/0.25.0) | **未声明** / Apache-2.0 OR MIT | 默认 feature set 为空；不要开 protobuf（[manifest/features](https://docs.rs/crate/prometheus-client/0.25.0/source/Cargo.toml)） | 一个 type-safe registry + text encoder 即可；不同时引入另一套 metrics facade/exporter。 |
| [`aes-gcm 0.11.0`](https://crates.io/api/v1/crates/aes-gcm/0.11.0) | 1.85 / Apache-2.0 OR MIT | `default-features=false`; `aes,bytes,zeroize`；不要开 `alloc,getrandom,hazmat`（[manifest](https://docs.rs/crate/aes-gcm/0.11.0/source/Cargo.toml.orig)） | `Aes128Gcm`、96-bit nonce、in-place `BytesMut`、16-byte tag；salt RNG 由注入边界负责。 |
| [`blake3 1.8.5`](https://crates.io/api/v1/crates/blake3/1.8.5) | **未声明**；Edition 2024 / CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | `default-features=false`; `std,zeroize`；不要开 `mmap,rayon,traits-preview`（[manifest/features](https://docs.rs/crate/blake3/1.8.5/source/Cargo.toml)） | SIP022 KDF。用 incremental hasher 依次 update PSK/salt，显式 zeroize state/output，避免 `concat()` secret copy。 |
| [`base64 0.23.0`](https://crates.io/api/v1/crates/base64/0.23.0) | 1.71.0 / MIT OR Apache-2.0 | `default-features=false`; `std`，从而不启用默认 `simd-unsafe`（[feature map](https://docs.rs/crate/base64/0.23.0/features)） | 严格 Standard Base64 解码；解码后再强制 exact 16-byte length。 |
| [`zeroize 1.9.0`](https://crates.io/api/v1/crates/zeroize/1.9.0) | 1.85 / Apache-2.0 OR MIT | `default-features=false`; `alloc,derive`（[feature map](https://docs.rs/crate/zeroize/1.9.0/features)） | fixed PSK/subkey types、临时 config strings 和 buffers 的显式清理。 |
| [`getrandom 0.4.3`](https://crates.io/api/v1/crates/getrandom/0.4.3) | 1.85 / MIT OR Apache-2.0 | `default-features=false`; `std`；Windows/Linux 不需 wasm/custom backend（[feature map](https://docs.rs/crate/getrandom/0.4.3/features)） | 小而明确的 OS random source；包在可注入、可失败的 ferrum2 entropy trait 后，用于 salt/padding。 |
| [`clap 4.6.4`](https://crates.io/api/v1/crates/clap/4.6.4) | 1.85 / MIT OR Apache-2.0 | `default-features=false`; `std,derive,help,usage,error-context`（[feature map](https://docs.rs/crate/clap/4.6.4/features)） | 两个 binary 的 config path、offline validate、help/exit contract；不需要 color/suggestions/env。 |
| [`thiserror 2.0.19`](https://crates.io/api/v1/crates/thiserror/2.0.19) | 1.71 / MIT OR Apache-2.0 | 默认 `std`（[feature map](https://docs.rs/crate/thiserror/2.0.19/features)） | typed internal errors；面向 operator 的显示文本必须 redacted。 |

建议在 `[workspace.dependencies]` 使用 exact requirements（`=version`），并提交
`Cargo.lock`。每个 crate 只在实际调用它的 crate 中列为 direct dependency；
不要把整张表复制到每个 member。

### C2. 评估过但 M0 不直接引入

| crate | 当前来源事实（查询日 2026-07-27） | 建议 |
|---|---|---|
| [`metrics 0.24.6`](https://crates.io/api/v1/crates/metrics/0.24.6) + [`metrics-exporter-prometheus 0.18.3`](https://crates.io/api/v1/crates/metrics-exporter-prometheus/0.18.3) | 两者 `rust-version` 均为 1.71.1；需要 facade + recorder/exporter 两层。 | M0 直接用 `prometheus-client`，让 label 类型和 registry ownership 可审核。若以后必须替换 backend，再用 ADR 引入 facade。 |
| [`secrecy 0.10.3`](https://crates.io/api/v1/crates/secrecy/0.10.3) | `rust-version=1.60`，Apache-2.0 OR MIT。 | M0 只有固定 16-byte PSK；本地 newtype + redacted `Debug` + `ZeroizeOnDrop` 更窄。未来 secret 种类/暴露策略复杂后再评估。 |
| [`subtle 2.6.1`](https://crates.io/api/v1/crates/subtle/2.6.1) | 未声明 `rust-version`；BSD-3-Clause；`aes-gcm` 已间接依赖。 | M0 没有需要直接 constant-time 比较的 secret verifier；response salt 是公开 wire binding。不要只为“看起来安全”增加 direct dependency。 |
| [`rand 0.10.2`](https://crates.io/api/v1/crates/rand/0.10.2) | `rust-version=1.85`；默认启用 thread RNG/std RNG/sys RNG。 | M0 只需填充 salt 和小范围 padding；直接 `getrandom::fill` + 本地无偏 rejection sampling + injected test source 更窄。若 M1/M2 需要 distributions/Rng trait，再评估。 |

### C3. 依赖风险与验证动作

- **来源事实：** `blake3 1.8.5` 的
  [build.rs](https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/build.rs)
  在 x86_64 默认尝试 assembly/C compiler 路径；检测不到 compiler 时可退回 pure
  Rust。其 `pure` feature 在 manifest 中被上游标为主要用于测试/benchmark 的
  undocumented unstable feature。
- **建议：** 不依赖 `pure` feature；三个 target build 记录 compiler/build-script
  输出。M4 benchmark 必须固定 C toolchain/backend，否则同一 source 可能得到不同
  性能基线。M0 functional smoke 仍须在无 C compiler fallback 与正常 optimized
  build 中至少有一条显式证据。
- `blake3` 的 `zeroize` feature 只是提供 `Zeroize` impl，不保证所有临时 state
  自动 drop 清除；production KDF 必须显式清理 hasher、32-byte output 和 16-byte
  subkey owner。
- `prometheus-client` 未声明 MSRV；把 1.85.0 resolved-graph build 设为 blocking
  gate，不在研究阶段推断其 MSRV。
- M0 选中的 direct license expressions 均为 permissive/CC0 类上游声明，但仍需对
  **完整 `Cargo.lock` transitive graph** 做一次 license/provenance review；本笔记
  不是法律意见。

## D. 固定参考实现与 AES-128 TCP 双向互操作入口

### D1. release、commit 与许可

| Reference | 当前可固定 release / commit | 上游许可事实 | 查询日 |
|---|---|---|---|
| sing-box | [v1.13.14 stable release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.14)，发布于 2026-06-25；tag 直接指向 [`25a600db24f7680ad9806ce5427bd0ab8afe1114`](https://github.com/SagerNet/sing-box/commit/25a600db24f7680ad9806ce5427bd0ab8afe1114)。查询日已有 1.14 prerelease，但不是 stable pin。 | 固定 [LICENSE](https://github.com/SagerNet/sing-box/blob/v1.13.14/LICENSE) 写明 GPL v3 or later，并另有禁止 derivative 使用名称/暗示关联的附加文字；GitHub API 因而给出 `NOASSERTION`，不应擅自简化成单一 SPDX 表达式。 | 2026-07-27 |
| shadowsocks-rust | [v1.24.0 stable release](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.24.0)，发布于 2025-12-10；tag 直接指向 [`7ee1aa9223ed8f4d34734aac919036c8ad4502c2`](https://github.com/shadowsocks/shadowsocks-rust/commit/7ee1aa9223ed8f4d34734aac919036c8ad4502c2)。 | 固定 [LICENSE](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.24.0/LICENSE) 和 root [Cargo.toml](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.24.0/Cargo.toml) 均声明 MIT。 | 2026-07-27 |

**建议：** 两者都只作为下载后按 checksum 验证的测试进程。不要 vendor source、
link protocol core 或提交 binary。sing-box 在 redistribution、fixture/code copy
前必须有明确 license review。

可直接固定的 x86_64 host assets：

| Reference / host | release asset | GitHub release SHA-256（查询日 2026-07-27） |
|---|---|---|
| sing-box / Linux glibc | [sing-box-1.13.14-linux-amd64-glibc.tar.gz](https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64-glibc.tar.gz) | `aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6` |
| sing-box / Windows | [sing-box-1.13.14-windows-amd64.zip](https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-windows-amd64.zip) | `f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341` |
| shadowsocks-rust / Linux glibc | [shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz](https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz) | `5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65` |
| shadowsocks-rust / Windows MSVC | [shadowsocks-v1.24.0.x86_64-pc-windows-msvc.zip](https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/shadowsocks-v1.24.0.x86_64-pc-windows-msvc.zip) | `8f4bdd02cf3b42976f6b48e01239bc0ae61f9da7a3c260505a7880de615291d0` |

不要使用 `latest` URL/tag。test plan 应固定实际 runner 对应的 asset name、size、
SHA-256 和解压后 `version` 输出。

### D2. 官方可用入口

**sing-box 来源事实：**

- 固定版本的
  [Shadowsocks inbound 文档](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/inbound/shadowsocks.md)
  和
  [outbound 文档](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/outbound/shadowsocks.md)
  均列出 `2022-blake3-aes-128-gcm`，key length 16，2022 password 是对应长度的
  base64 key；两者都有 `network: "tcp"`。
- 固定版本有
  [SOCKS inbound](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/inbound/socks.md)。
  CLI source 定义 `sing-box run` 和 persistent `-c/--config`：
  [cmd.go](https://github.com/SagerNet/sing-box/blob/v1.13.14/cmd/sing-box/cmd.go)、
  [cmd_run.go](https://github.com/SagerNet/sing-box/blob/v1.13.14/cmd/sing-box/cmd_run.go)。

**shadowsocks-rust 来源事实：**

- 固定 root
  [Cargo.toml](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.24.0/Cargo.toml)
  的 default `full` features 包含 `local`、`server`、`aead-cipher-2022`；binaries 是
  `sslocal` 和 `ssserver`。
- 固定
  [README](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.24.0/README.md)
  列出 `2022-blake3-aes-128-gcm`，要求 password base64 decode 后与 cipher key
  size 完全相同，并给出 `sslocal -c config.json` / `ssserver -c config.json`。
- config source 接受 `mode = "tcp_only"`：
  [固定 config.rs](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.24.0/crates/shadowsocks-service/src/config.rs)。

### D3. 四个 M0 required cases

以下是**建议的 harness contract**：

| Case | reference 进程 | ferrum2 进程 | 数据入口 |
|---|---|---|---|
| 1 | sing-box Shadowsocks inbound + direct outbound | `ferrum2-client` | 对 ferrum2 SOCKS5 发 TCP `CONNECT` 到 local echo |
| 2 | sing-box SOCKS inbound + Shadowsocks outbound | `ferrum2-server` + direct outbound | 对 sing-box SOCKS5 发 TCP `CONNECT` 到 local echo |
| 3 | `ssserver -c`, `mode=tcp_only` | `ferrum2-client` | 对 ferrum2 SOCKS5 发 TCP `CONNECT` 到 local echo |
| 4 | `sslocal -c`, `mode=tcp_only` | `ferrum2-server` + direct outbound | 对 sslocal SOCKS5 发 TCP `CONNECT` 到 local echo |

所有 case：

- 只启用 `2022-blake3-aes-128-gcm`、TCP、单 PSK、loopback；关闭 UDP、plugin、
  multiplex、multi-user/EIH、额外 routing。
- 使用同一个明确标注为 test-only 的 fixed 16-byte synthetic PSK；配置文件不得被
  debug 打印或作为失败 artifact 无审查上传。
- 分配不冲突的 loopback ports，等待进程 ready 后再驱动 SOCKS5；echo 同时覆盖
  client→target 与 target→client bytes、半关闭和 target refusal。
- 每个 case 是独立 required result；一个方向成功不能代替反方向。reference
  binary 缺失、下载失败或 runner 不可用时 job 必须 fail/blocked，不能 silent skip。
- 保存版本、asset checksum、精简配置 checksum、命令、exit status 和 sanitized
  logs；不保存 PSK、salt、nonce、destination 为 metric labels。

## E. 三个官方 Rust target

### E1. 支持级别与构建事实

目标支持事实来自 Rust 1.97.1 当前
[rustc Platform Support](https://doc.rust-lang.org/rustc/platform-support.html)
和 [Windows MSVC target 说明](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html)；
查询日 2026-07-27。

| exact target | 官方级别/下限（来源事实） | 构建注意点与建议 |
|---|---|---|
| `x86_64-pc-windows-msvc` | Tier 1 with host tools；Windows 10+ / Server 2016+；完整 std。官方文档说最低 VS 2017，但强烈建议当前 VS 2022。 | 在 Windows x86_64 runner 安装 VS 2022 Build Tools 的 C++ workload，并原生 build/run。Rust 官方不支持从 non-Windows host 交叉到 MSVC；不要用该路径作为 gate。 |
| `x86_64-unknown-linux-gnu` | Tier 1 with host tools；Linux kernel 3.2+、glibc 2.17+；完整 std。 | 在固定 x86_64 glibc Linux image/sysroot 原生 build/run。Rust target 下限不自动保证在新发行版链接出的 binary 只需要 glibc 2.17；记录 builder image，并检查 artifact 的 required GLIBC symbols。 |
| `x86_64-unknown-linux-musl` | Tier 2 with host tools；musl 1.2.5；完整 std。Tier 2 保证官方 build artifact，但不保证持续运行完整 tests。 | 必须有 artifact-level run smoke。Rust 1.97.1 target source将 `crt_static_default=true`（[固定 target source](https://github.com/rust-lang/rust/blob/1.97.1/compiler/rustc_target/src/spec/targets/x86_64_unknown_linux_musl.rs)）；若 M0 contract 采用默认 static，使用 `file`/`readelf` 验证并在 Linux runner 实际运行。 |

**来源事实：** [`rustup target add`](https://rust-lang.github.io/rustup/cross-compilation.html)
只安装目标的 Rust standard library；通常仍需相应 linker/SDK/C toolchain。

### E2. 建议的 M0 platform smoke

1. 固定 compiler 为 1.97.1，并先安装三个 exact targets。每个 target 执行：

   ```text
   cargo build --workspace --bins --locked --target <triple>
   ```

   M0 test plan 决定 debug/release；至少最终 integration evidence 使用 release artifact。
2. 在匹配环境分别运行 `ferrum2-client` 和 `ferrum2-server` 的 offline
   config-validation command，输入一个合法 synthetic TOML 和一个错误 AES-128 key
   length TOML；断言无 listener 被创建、exit code/error category 稳定且不泄密。
3. Windows artifact 在 Windows runner 运行；GNU artifact 在 glibc Linux runner
   运行；默认静态 musl artifact 可在 Linux runner 运行，但仍要验证静态链接事实。
4. `cargo check --target`、只链接 library、或只在 build host 检查文件存在，都不算
   binary artifact smoke。
5. 记录 rustc/cargo version、target triple、linker/C compiler version、builder
   image digest、artifact SHA-256、run command 和 exit status。BLAKE3 build backend
   也要记录，避免 compiler 可用性导致静默性能差异。

## M0 计划需要显式关闭的剩余风险

| 风险/未决点 | 这份研究提供的边界 | M0 仍需的决策/证据 |
|---|---|---|
| SIP022 没有版本号/KAT | 已给 official commit/blob 和 primitive vector 来源 | ADR 接受快照；spec/test plan 创建并审查非官方 protocol KAT |
| AES-128 KDF/nonce 细节未在规范中完全展开 | 已标出 BLAKE3 32→16 截断与 zero nonce 的 reference behavior | spec 明写，KAT + 两 references 双向验证 |
| exact replay set 可能资源耗尽 | 规范要求 60 秒且禁止 false positive | capacity、clock、concurrency、满载 fail-closed 策略和负向测试 |
| detection prevention 跨 OS 可观察行为 | 规范策略和 `socket2` 入口已定位 | 选定策略；逐 byte probe 覆盖 Windows/glibc/musl |
| dependency MSRV 并非全声明 | 推荐 MSRV 1.85，指出两个无声明 crate | 1.85.0 locked graph gate；失败则 pin compatible release 或提高 MSRV |
| reference 漂移/许可 | 固定 release/commit/assets/checksums；sing-box license 有附加文字 | 黑盒使用 policy、下载/cache policy、license review、required-job policy |
| target build 不等于 artifact 可运行 | 已区分 Tier 1/Tier 2 和 linker要求 | 三个 matching-runner offline smoke、glibc/musl linkage evidence |

## Primary-source 索引

- [SIP022 live page](https://shadowsocks.org/doc/sip022.html)
- [SIP022 fixed official-site source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [Cargo `rust-version`](https://doc.rust-lang.org/cargo/reference/rust-version.html)
- [Rust 1.97.1 fixed channel manifest](https://static.rust-lang.org/dist/2026-07-16/channel-rust-stable.toml)
- [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html)
- [rustup cross-compilation](https://rust-lang.github.io/rustup/cross-compilation.html)
- [sing-box v1.13.14](https://github.com/SagerNet/sing-box/releases/tag/v1.13.14)
- [shadowsocks-rust v1.24.0](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.24.0)
- 每个 crate 的固定 crates.io metadata/docs.rs 链接见 C 节表格。
