# Ferrum2

Ferrum2 是一个使用 Rust 2024 编写的代理工作区，包含 SOCKS5 客户端和代理服务端，
支持 Shadowsocks 2022 TCP/UDP、路由规则、DNS 策略、
远程二进制 RuleSet，以及 Windows x86_64 上的托管 Wintun。

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

服务端 `inbounds[].listen` 支持 IPv4 或带方括号的 IPv6 地址，例如 `[::1]:8388`；
IPv6 TCP/UDP 监听为 IPv6-only，不隐式接收 IPv4-mapped 流量。两端的 `metrics.listen`
只接受回环地址，可使用 `127.0.0.1:9091` 或 `[::1]:9091`。客户端 SOCKS5 监听仍限 IPv4。

## 内嵌仪表盘

client 内嵌 React 仪表盘，提供连接、出站选择、路由、DNS、日志与配置管理。
前端发布为一个 HTML，运行 client 不需要 Bun、Node.js 或独立 Web 服务。

先按[仪表盘架构与使用说明](docs/architecture/dashboard-design.md#running-the-dashboard)
创建私有令牌文件，再启动：

```text
cargo run -p ferrum2-client --locked -- --config client.toml --dashboard-listen 127.0.0.1:9090 --dashboard-token-file dashboard.token --dashboard-details
```

使用打印的本机 URL，在页面输入令牌。省略 `--dashboard-details` 可隐藏连接地址；
关闭页面不会停止代理。修改配置与重启使用现有运行时清理机制，不绕过 TUN 权限。

## 配置与文档

`--check-config` 只解析和验证配置，不进行 DNS、HTTP、监听或 TUN 操作。
`--check-config --materialize` 进一步解析固定端点并加载、编译 RuleSet，可能联网及读写缓存，
但不启动监听器或创建 TUN。普通启动会先完成同样的资源准备。

- [文档索引](docs/README.md)：配置、架构、验证流程和性能证据。
- [DNS 与 RuleSet 配置](docs/config-v2-dns-rulesets.md)。
- [Windows TUN 配置](docs/config-v2-tun.md)：当前 schema-v2 字段、系统 TCP、原生 UDP 和网络生命周期。
- [内嵌 rocom 录制与离线解码](docs/architecture/rocom-recording-design.md)：自动识别 TSF4G 连接，每条连接独立保存原始数据/key JSONL，普通 TCP 不录制；敏感录制须显式开启。
- [Windows TUN 正确性验证](docs/windows-tun-qualification.md)：真实网卡验证的专用流程。
- [性能证据说明](docs/performance-evidence.md)：Linux 配对测量与 TUN-only mock I/O 基准、A/A 校准和证据验证。
- [Rule 性能控制器](tools/performance_rule/README.md)：校准前置检查、请求绑定与有界证据保留。
- [TUN 系统 TCP 设计](docs/architecture/tun-system-tcp-design.md)：TCP 交给 Windows、UDP 保持原生；已选定最小临时入站放行与受管宿主机验证。

## 开发与验证

可执行入口在 `bins/`，共享实现位于 `crates/`；跨进程测试在 `tests/m0-harness/`，
共享测试输入在 `tests/fixtures/`，验证工具及 CI 控制器在 `tools/`。
各目录的 `AGENTS.md` 记录其职责、边界和相关命令。

完整命令和平台前提见[贡献指南](AGENTS.md)，CI 门禁见[门禁清单](docs/architecture/gates.md)。
普通测试中客户端测试二进制只编译，TUN 和 Windows 平台库使用关闭默认特性的安全测试入口。
TUN 性能使用 crate-owned `tun-benchmark`，只运行真实 TUN 逻辑与有界内存 I/O，不需要管理员权限。
真实 Windows TUN 正确性运行仍需要已提升权限的 shell 和显式
`-AcknowledgeHostNetworkMutation`，由唯一资格 runner 验证持续传输、重置及零残留。

```text
cargo build -p ferrum2-tun --example tun-benchmark --no-default-features --features benchmark --profile profiling --locked
```

Windows 可运行 `target/profiling/examples/tun-benchmark.exe --scenario tcp-rewrite --mode Quick`；
Unix 省略 `.exe`。单场景输出只是内部处理成本观察，正式比较按性能指南执行校准和配对。
