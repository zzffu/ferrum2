# M5 `shadowsocks-crypto` 迁移基线

- **Status:** Reviewed planning baseline
- **Date:** 2026-08-02
- **Milestone:** M5
- **Planning baseline:** `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`

## 结论

M5 选择 `shadowsocks-crypto 0.7.0` 作为 `ferrum2-crypto` 唯一的产品密码
实现，但 crates.io 原包不能直接满足 ferrum2 的安全合同。迁移必须使用精确来源的
受控 patch，并保留一个薄 adapter；不得保留旧 cipher/KDF、fallback 或运行时开关。

固定上游身份：

| Item | Value |
|---|---|
| Package | `shadowsocks-crypto 0.7.0` |
| crates.io archive SHA-256 | `9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0` |
| Packaged VCS commit | `2affa6c39b30f7626137a1792c533610cf133ade` |
| License | MIT |
| Declared package MSRV | Rust 1.71 |
| Ferrum selected feature | `default-features = false`, `features = ["v2"]` |

`v2-extra` enables `chacha20poly1305/reduced-round` and
`2022-blake3-chacha8-poly1305`，因此不得出现在任何 ferrum dependency edge 或
resolved feature set。默认 `v1`/`v1-aead`、`ring` 和 `aws-lc` 同样不启用。

## 当前 ferrum2 实现

`crates/ferrum2-crypto/src/lib.rs` 在 baseline 有 1,841 行，并同时拥有：

- `derive_subkey_16/32` 与 `derive_udp_subkey_16/32` BLAKE3 KDF；
- `TcpCipher`、`TcpSealer`、`TcpOpener` 与私有 u96le nonce owner；
- AES UDP separate-header block cipher、AES-GCM body 与 XChaCha envelope；
- method/key/salt、CSPRNG、UDP session/counter 和 redacted error 的公开 seam。

`crates/ferrum2-shadowsocks/src/lib.rs` 与 `src/udp.rs` 只消费该公开 seam，并拥有
framing、timestamp、binding、replay、session 和 mutation ordering。M5 不把这些
状态机移入上游 crate，也不修改 wire/config 行为。

产品正常依赖目前直接包含 `aes`、`aes-gcm`、`ghash`、`blake3` 和
`chacha20poly1305`。迁移完成后，只有独立 KAT/fixture test oracle 仍可把需要的
primitive 保留为 dev dependency；产品正常图不得再直接拥有它们。

## 原包差距

对 0.7.0 packaged source 的检查发现：

1. `v2::tcp::TcpCipher::increase_nonce` 静默回绕；`decrypt_packet` 即使认证失败也
   推进 nonce。它不能直接替代 ferrum2 的 exhaustion-before-use、成功后 commit
   语义。
2. TCP 与 AES-UDP KDF 使用普通 `Vec`/`BytesMut` 保存 `PSK || salt/session ID`
   和 derived key；原包没有清零这些临时 secret-bearing buffer。
3. `v2::udp::UdpCipher` 只处理 AEAD body。AES-UDP 的 16-byte separate header
   protection 在 shadowsocks-rust 中另由 `aes` 直接完成；直接采用该 API 会让
   ferrum2 继续保留第二个 AES 实现。
4. `utils::random_iv_or_salt` 含一个 `unsafe align_to`，且 `rand` 对仅启用 `v2`
   仍是无条件依赖；ferrum2 使用现有 `SecureRandom`/`getrandom` seam，不需要它。
5. 原包 primitive wrapper 的 encrypt API 对不合法长度 panic。ferrum2 adapter
   必须先验证容量，并把可发生的失败映射回现有 closed errors。

因此单纯 wrapper 不足。受控 patch 的唯一允许范围是：

- 为 ferrum2 所需 TCP/UDP primitive 操作提供 checked、nonce-explicit 或等价的
  fail-closed API；
- 把 KDF 输入、derived key、展开密钥和其他 secret owner 纳入可审计 zeroization；
- 把 AES-UDP header protection 收进该 crate；
- 移除 selected `v2` 图中的无用 `rand` 与 `unsafe`；
- 保留上游 LICENSE、版本、来源/checksum 和逐项 patch provenance。

不得把 ferrum2 protocol state、routing、config、replay 或 multi-user/EIH 放进
patch；不得增加第二个 backend、fallback 或 runtime selector。

## 现有证据可复用性

- `crates/ferrum2-crypto/tests/{primitive_vectors,sip022_vectors,secret_entropy}.rs`
  已覆盖三方法 KDF/AEAD/UDP composite fixture、corrupted tags、entropy、redaction、
  zeroize traits、TCP u96le exhaustion 与 UDP u64 exhaustion。
- `crates/ferrum2-shadowsocks/tests/**` 已覆盖 TCP/UDP exact wire、负向语义、
  replay、binding、allocation ordering 和 state mutation。
- `.github/workflows/m0.yml` 已在一个 exact SHA/run/attempt 上运行 Full、Rust
  1.85、三目标、TCP/UDP `24/24` 和 M4 performance；M5 复用它，不新增 workflow。
- Planning probe 已用 Rust 1.85.0 对原包
  `--no-default-features --features v2` 完成 `cargo check`。这只证明未打 patch 的
  上游 source 能编译，不是 M5 MSRV、security 或 dependency PASS。

## 仍待执行关闭的审查

最终 patched/locked graph 的 package identities、features、licenses、MSRV、
unsafe/zeroize source、KAT/negative、外部 TCP/UDP 互操作和 performance 只能在
M5 exact integration candidate 上审查。任一项失败、缺失或 provider/remote
不可用都使 M5 `blocked`；不得以恢复旧实现、保留 fallback 或拼接旧 run 关闭。

## Primary sources

- [crates.io package](https://crates.io/crates/shadowsocks-crypto/0.7.0)
- [Upstream packaged commit](https://github.com/shadowsocks/shadowsocks-crypto/tree/2affa6c39b30f7626137a1792c533610cf133ade)
- [0.7.0 API documentation](https://docs.rs/shadowsocks-crypto/0.7.0/shadowsocks_crypto/)
- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- `docs/research/M0-upstream-baseline.md`
- `docs/research/M1-tcp-method-baseline.md`
- `docs/research/M2-udp-baseline.md`
