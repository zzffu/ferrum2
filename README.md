# Ferrum2

Ferrum2 是一个使用 Rust 2024 编写的代理工作区，包含 SOCKS5 客户端和 Shadowsocks
服务端，支持 Shadowsocks 2022 TCP/UDP、路由规则、DNS 策略、远程二进制 RuleSet，以及
Windows x86_64 上的托管 Wintun。

当前仅接受 `schema_version = 2`，不提供旧配置兼容层或自动迁移。许可证为
[GPL-3.0-only](LICENSE)。

## 构建

[rust-toolchain.toml](rust-toolchain.toml) 固定 Rust **1.97.1**；使用 rustup 管理工具链，
并准备目标平台的原生编译工具。Windows 构建使用 MSVC 工具链及 Windows SDK。
仓库的原生 CI 目标是 Windows MSVC、Linux GNU 和 Linux musl，均为 x86_64。
Linux 上支持普通代理功能，托管 TUN 后端仅支持 Windows x86_64。

在仓库根目录运行：

```text
cargo build -p ferrum2-client -p ferrum2-server --bins --locked
cargo run -p ferrum2-client --locked -- --help
cargo run -p ferrum2-server --locked -- --help
```

默认调试二进制位于 `target/debug/`；Windows 文件带 `.exe` 后缀。
发布构建追加 `--release`，输出位于 `target/release/`。指定 `--target` 时，输出目录变为
`target/<target>/<debug|release>/`。

## 本机 SOCKS5 示例

这组示例使用回环地址和公开的合成测试密钥，便于在本机检查配置并运行客户端/服务端：

- [客户端配置](docs/examples/client-v2-socks5.toml)：SOCKS5 监听 `127.0.0.1:1080`，
  经 Shadowsocks 连接 `127.0.0.1:8388`。
- [服务端配置](docs/examples/server-v2.toml)：监听 `127.0.0.1:8388`，使用 Direct 出站。

先执行离线校验：

```text
cargo run -p ferrum2-server --locked -- --config docs/examples/server-v2.toml --check-config
cargo run -p ferrum2-client --locked -- --config docs/examples/client-v2-socks5.toml --check-config
```

在两个终端中分别启动服务端和客户端：

```text
cargo run -p ferrum2-server --locked -- --config docs/examples/server-v2.toml
cargo run -p ferrum2-client --locked -- --config docs/examples/client-v2-socks5.toml
```

将应用的 SOCKS5 代理设为 `127.0.0.1:1080`，结束时使用 Ctrl+C。
这些示例启用 TCP 和 UDP；应用使用 UDP 时需要支持 SOCKS5 UDP ASSOCIATE。
用于真实部署前，应复制配置、替换测试密钥和地址，并保持两端方法和密钥一致。
SOCKS5 入站为无认证模式，示例因此只监听回环地址。

## 配置与文档

`--check-config` 只解析和验证配置，不进行 DNS、HTTP、监听或 TUN 操作。
`--check-config --materialize` 进一步解析固定端点并加载、编译 RuleSet，可能联网及读写缓存，
但不启动监听器或创建 TUN。普通启动会先完成同样的资源准备。

- [文档索引](docs/README.md)：配置、架构、验证流程和性能证据。
- [DNS 与 RuleSet 配置](docs/config-v2-dns-rulesets.md)。
- [Windows TUN 配置](docs/config-v2-tun.md)与[旧网络模型迁移说明](docs/network-model-v2-migration.md)。
- [Windows TUN 正确性验证](docs/windows-tun-qualification.md)：真实网卡验证的专用流程。
- [性能证据说明](docs/performance-evidence.md)：Linux 配对测量和 Windows 主机性能流程。
- [工程整改记录](docs/architecture/engineering-remediation-2026-09-05.md)：审查覆盖、故障复现、修复与验证缺口。

## 开发与验证

可执行入口在 `bins/`，共享实现位于 `crates/`；跨进程测试在 `tests/m0-harness/`，
共享测试输入在 `tests/fixtures/`，验证工具及 CI 控制器在 `tools/`。
各目录的 `AGENTS.md` 记录其职责、边界和相关命令。

完整命令和平台前提见[贡献指南](AGENTS.md)，CI 门禁见[门禁清单](docs/architecture/gates.md)。
普通测试中客户端测试二进制只编译，TUN 和 Windows 平台库使用关闭默认特性的安全测试入口。
真实 Windows TUN 正确性或性能运行需要已提升权限的 shell 和显式
`-AcknowledgeHostNetworkMutation`，并由相应专用 runner 完成资源回收。
