# ADR-0006: M0 互操作 provenance 与平台证据

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T08；关闭 DEC-007；external half-close sequence 由 `ADR-0014` 显式细化，evidence-mechanism替换边界由`ADR-0016`规范

## Context and problem

M0 把 AES-128 TCP 双向 reference interoperability 和三个目标的 binary smoke
前移为退出门。若使用 `latest`、未校验下载、环境缺失时 skip，成功证据不可复现；
若 vendor/link/copy reference protocol core，又会破坏独立实现和 license boundary。
仓库当前没有 CI provider/remote，因此 contract 必须 provider-neutral。

## Decision drivers and invariants

- ferrum2 必须独立实现 SIP022；reference 仅是黑盒进程。
- 两个 reference、两个方向是四个独立 required results，一个不能替代另一个。
- artifact 缺失、下载失败、checksum mismatch、runner unavailable、crash 或 timeout
  都是 FAIL/BLOCKED，不得 fallback/skip-pass。
- 外部 binaries、generated configs/logs、pcap 和 qualification results 不提交仓库。
- 三个目标必须 build 两个 release binaries，并在 matching ABI runner 实际运行
  valid/invalid offline config smoke。

## Options considered

### Option A：固定 release/commit/artifact checksum 的黑盒 harness

runtime 下载到 generated directory、先校验再执行，配置和端口隔离由 test harness
管理。

### Option B：跟随 reference `latest`

维护成本低，但 wire/CLI/license drift 会使同一 ferrum2 commit 得到不同结果。

### Option C：vendor/link reference protocol core 或 fixtures

降低 harness 工作，但不再是独立实现，也引入复制/分发及 provenance 风险。

## Decision

### Fixed references

M0 pin：

| Reference | Release / source commit | Host artifact | SHA-256 |
|---|---|---|---|
| sing-box | `v1.13.14` / `25a600db24f7680ad9806ce5427bd0ab8afe1114` | `sing-box-1.13.14-linux-amd64-glibc.tar.gz` | `aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6` |
| sing-box | same | `sing-box-1.13.14-windows-amd64.zip` | `f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341` |
| shadowsocks-rust | `v1.24.0` / `7ee1aa9223ed8f4d34734aac919036c8ad4502c2` | `shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz` | `5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65` |
| shadowsocks-rust | same | `shadowsocks-v1.24.0.x86_64-pc-windows-msvc.zip` | `8f4bdd02cf3b42976f6b48e01239bc0ae61f9da7a3c260505a7880de615291d0` |

`tests/interop/versions.toml` 保存 version、source commit、asset name、URL、size
（T08 下载时核实）、SHA-256、expected version output 和 license note。不得使用
`latest` URL。

sing-box 固定 LICENSE 是 GPL v3-or-later 加附加名称文字，GitHub SPDX 为
`NOASSERTION`；shadowsocks-rust 是 MIT。二者只作为独立 test process，不链接、
复制、提交或重新分发。任何 code/fixture copy 需另行 provenance/license review。

### Required four-case matrix

所有 case 使用 loopback、TCP-only、单 method、关闭 UDP/plugin/multiplex/
multi-user/EIH 和额外 routing；synthetic PSK 固定为
`AAECAwQFBgcICQoLDA0ODw==`：

1. `ferrum2-client` → sing-box Shadowsocks server → local IPv4 echo。
2. `ferrum2-client` → shadowsocks-rust `ssserver` → local IPv4 echo。
3. sing-box SOCKS client path → `ferrum2-server` → local IPv4 echo。
4. shadowsocks-rust `sslocal` → `ferrum2-server` → local IPv4 echo。

每项独立进程/临时目录/ephemeral ports，验证 client→target 和 target→client
pre-FIN bytes、ordered clean-EOF convergence、process cleanup。ADR-0014把
external case的顺序细化为：
先完整逐byte比较双向各16386-byte distinct payload，再由application client
write-half close、target deadline-observe clean `Ok(0)`后成功write-half close、
application client deadline-observe clean `Ok(0)`；该顺序不声明target FIN导致
client EOF。peer FIN后新产生reverse bytes的ferrum2要求仍由同一SHA的
M0-E2E-001/M0-LIFE-003独立阻塞，external PASS不得替代。T08 记录 reference
`--version`、asset checksum、sanitized config checksum、command category、exit
status 和 sanitized logs；不记录 PSK、salt/nonce 或 raw config。

外部 binaries 下载到 `target/interop-tools/` 或 runner temp，属于 generated
artifacts。harness 对每个 child 使用 readiness deadline、case timeout、bounded
stdout/stderr capture 和 kill-on-drop；任何 required case 未运行即 M0 未关闭。

### Platform and MSRV jobs

M0 provider-neutral required job names：

- `m0-msrv`
- `m0-windows-msvc`
- `m0-linux-gnu`
- `m0-linux-musl`
- `m0-interop-sing-box`
- `m0-interop-shadowsocks-rust`

MSRV：

```text
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
```

每个 target 在 Rust 1.97.1 执行：

```text
cargo +1.97.1 build --workspace --bins --release --locked --target <triple>
<client artifact> --config <valid-client.toml> --check-config
<client artifact> --config <invalid-client.toml> --check-config
<server artifact> --config <valid-server.toml> --check-config
<server artifact> --config <invalid-server.toml> --check-config
```

valid exit 0，invalid key-length exit 2；四次都证明未创建 listener。Windows 在
native Windows x86_64 + VS 2022 runner；GNU 在固定 x86_64 glibc Linux runner；
musl 安装相应 target/linker，在 Linux 实际运行默认静态 artifact，并用
`file`/`readelf` 记录链接属性。GNU 记录 builder image 和 required GLIBC symbols。
`cargo check`、只构建 library 或只检查 artifact 存在不能替代 smoke。

每项 evidence 记录 rustc/cargo、target、linker/C compiler、runner image、
BLAKE3 backend、artifact SHA-256、run command category 和 exit。CI provider 可在
后续接入，但不得改变 required semantics。

M0 的 detection native probe 至少在 Windows interop runner 和 Linux GNU
interop runner 阻塞执行；musl 的完整 close-observability matrix以及全平台长期
lifecycle qualification 留给 M3。M0 的三目标 binary build/config smoke不能延期。

### Protocol fixture provenance

官方 SIP022 没有完整 protocol KAT。T02/T03 的 composite fixture：

- 明确标注非官方；
- 使用ADR-0004逐byte固定的PSK/salts/timestamp/target/padding/payload inputs和
  `tests/fixtures/sip022/generator.rs`；`PROVENANCE.toml`记录generator/output
  SHA-256、toolchain、dependency versions/licenses；
- expected bytes 不由 ferrum2 production path 运行时生成；
- 通过 code review、primitive vectors 和四项 interop共同交叉验证。

reference interop 是独立 evidence，不得把 reference output改名为“官方 KAT”。

## Consequences and tradeoffs

### Positive

- reference drift、supply-chain substitution 和 silent skip 都会显式失败。
- 三目标证据验证真实 binary/CLI，而非仅证明 Rust library 可 type-check。
- contract 不绑定尚不存在的 CI provider。

### Negative

- external network/runners 不可用会阻塞 M0 close，即使产品代码本身正确。
- pinned versions/checksums 需要受控更新；sing-box license 附加文字要求谨慎处理。
- M0 只完成 build/config smoke，不能宣称 M3 的完整平台资格或 M4 性能。

## Compatibility and upstream divergence

固定规范优先；两 reference 共同出现的偏差也不能自动改写 ferrum2。若合法互操作
揭示 spec ambiguity，停止 gate，提交 ADR/spec revision 后再继续。不得复制为了
“兼容”而违反安全 ordering 的上游代码。

## Migration and rollback

更新 reference pin 必须单独审查 release、commit、asset size/checksum、license 与
四项互操作。rollback 删除 generated temp artifacts并回退 integration commit；
不得在 Git 中保存外部 binary。

## Verification plan

- M0-INT-001～004：四项黑盒互操作。
- M0-PLAT-001～003：三 target release artifact smoke。
- M0-MSRV-001：1.85.0 locked graph。
- M0-GATE-001～002：host quick 与 integration full。

## References

- `docs/adr/ADR-0007-m0-github-actions-ci-provider.md`（补充 M0 required CI provider、hosted runner 与 provider-native evidence 合同）
- `docs/research/M0-upstream-baseline.md`
- [sing-box v1.13.14](https://github.com/SagerNet/sing-box/releases/tag/v1.13.14)
- [shadowsocks-rust v1.24.0](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.24.0)
- [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html)
- [rustup cross-compilation](https://rust-lang.github.io/rustup/cross-compilation.html)
