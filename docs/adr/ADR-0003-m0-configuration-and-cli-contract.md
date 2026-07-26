# ADR-0003: M0 typed TOML 与离线 CLI contract

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T04、M0-T07；关闭 DEC-004

## Context and problem

两个独立二进制必须在不创建 listener、connector、runtime task 或 metrics endpoint
时完成 typed TOML 的完整语义验证。operator-facing syntax、defaults、错误分类和
exit code 若不在实现前冻结，会使两端行为漂移，也会让“离线无副作用”无法自动验收。

## Decision drivers and invariants

- config parse/validation 完成后才能初始化 tracing、Tokio runtime resource、socket、
  connector 或 metrics。
- 所有 table 拒绝未知字段；所有 input 有明确大小、范围和 cross-field constraint。
- config/error output 不回显 raw TOML、PSK、endpoint target 或 parser source snippet。
- M0 只接受 AES-128、单 PSK、TCP 和 IPv4 loopback test path。
- OS 端口是否已占用不是纯离线可知条件；离线只验证配置内部 endpoint 冲突。

## Options considered

### Option A：每个 binary 使用同一 config library，解析为 role-specific validated type

共享 lexical/error policy，同时由 `ValidatedClientConfig` 与
`ValidatedServerConfig` 消除 run-time 的非法状态。

### Option B：binary 自行反序列化通用 `toml::Value`

初期灵活，但 unknown fields、defaults、secret redaction 和 cross-field validation
会分散到 composition root。

### Option C：通过 bind/listen 试运行来“验证”配置

可以发现 OS 端口占用，但违反离线 contract，并把环境瞬态误作配置语义。

## Decision

### CLI

两个 binary 采用相同 surface：

```text
ferrum2-client --config <PATH> [--check-config]
ferrum2-server --config <PATH> [--check-config]
ferrum2-{client,server} --help
ferrum2-{client,server} --version
```

- 有 `--check-config`：只读取、解析、语义验证；成功 stdout **恰好**
  `configuration valid\n`，stderr 为空，exit `0`。
- 无 `--check-config`：验证成功后才初始化日志/runtime/listeners 并运行服务。
- CLI usage error exit `2`；config I/O、文件过大、syntax 或 semantic error 也 exit
  `2`，但用稳定 code 区分。
- run-mode fatal error exit `1`；收到支持的 shutdown signal 且完成 shutdown exit
  `0`。
- operator error 是单行
  `error[<code>] <field-or-config>: <redacted-message>\n`。稳定 code 为
  `config.io`、`config.too_large`、`config.syntax`、`config.semantic`；
  不透传 parser/source `Display`。

### 通用 lexical contract

- 文件必须是 UTF-8，最大 `1,048,576` bytes；超限在解析前拒绝。
- root 与每个 nested struct 使用 `deny_unknown_fields`。
- `schema_version` 必须是整数 `1`。
- socket address 是显式 IP literal + port；端口 `0` 拒绝。M0 不在 config 中执行
  DNS。
- PSK 只接受 canonical RFC 4648 standard padded base64；解码后必须恰好 16 bytes。
  例如 repository synthetic key 为 `AAECAwQFBgcICQoLDA0ODw==`。
- `method` 只接受精确字符串 `2022-blake3-aes-128-gcm`；另外两个 v0 方法在 M1
  才加入 validated enum。

### Client schema

```toml
schema_version = 1

[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[runtime]
max_connections = 4096
listen_backlog = 1024
handshake_timeout_ms = 5000
connect_timeout_ms = 10000
idle_timeout_ms = 300000
shutdown_grace_ms = 30000

[logging]
level = "info"

# optional；缺失时不启动 metrics listener
[metrics]
listen = "127.0.0.1:9090"
```

### Server schema

```toml
schema_version = 1

[server]
listen = "127.0.0.1:8388"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[runtime]
max_connections = 4096
listen_backlog = 1024
handshake_timeout_ms = 5000
connect_timeout_ms = 10000
idle_timeout_ms = 300000
shutdown_grace_ms = 30000

[replay]
capacity = 65536

[logging]
level = "info"

[metrics]
listen = "127.0.0.1:9091"
```

### Defaults、ranges 与 cross-field validation

必需性与default policy固定为：

- root `schema_version`、role table（`[client]`或`[server]`）及其全部address fields、
  `[shadowsocks]`、`method`、`psk` 是required。
- `[runtime]` 是optional；缺失时使用下表全部defaults。table存在时每个field仍是
  optional并独立default，unknown field拒绝。
- server-only `[replay]` 是optional，`capacity` default 65536；client出现该table
  拒绝。server出现`[client]`或client出现`[server]`也作为unknown role table拒绝。
- `[logging]` 是optional，`level` default `info`。
- `[metrics]` 是optional；缺失时禁用endpoint。table存在时`listen`是required，
  不提供隐式port/address。
- 不读取environment variable覆盖、不插值、不merge多个文件。

数值defaults与ranges：

| Field | Default | Inclusive range / enum |
|---|---:|---|
| `max_connections` | 4096 | `1..=65535` |
| `listen_backlog` | 1024 | `1..=65535` |
| `handshake_timeout_ms` | 5000 | `100..=60000` |
| `connect_timeout_ms` | 10000 | `100..=120000` |
| `idle_timeout_ms` | 300000 | `1000..=86400000` |
| `shutdown_grace_ms` | 30000 | `0..=300000` |
| `replay.capacity` | 65536 | `1024..=1048576` |
| `logging.level` | `info` | `error`、`warn`、`info`、`debug`、`trace` |

`metrics.listen` 若存在必须是 loopback IP，且不得与该进程的 proxy listener 相同。
client 的 `client.listen` 与 `client.server` 不得相同。所谓 bind conflict 仅指这些
静态相等关系；另一进程已经占用端口只能在 run mode bind 时产生 runtime error。
M0 relay application buffer不是operator配置项，固定为每方向16384 bytes；改变该
数值需要runtime contract revision，而不是接受后忽略一个TOML字段。

### Parse/validate boundary

`ferrum2-config` 暴露：

```text
load_client(path) -> Result<ValidatedClientConfig, ConfigError>
load_server(path) -> Result<ValidatedServerConfig, ConfigError>
```

返回 validated type 前完成全部 lexical、range、method/key、role 和 cross-field
检查。validated types 的字段使用 `SocketAddr`、closed enum、duration/newtype 和
secret owner，不保留 raw TOML。binary 的 `--check-config` path 不构造 Tokio
runtime、listener、connector、tracing subscriber 或 metrics registry/listener。

## Consequences and tradeoffs

### Positive

- 两端 CLI/error contract 可用同一 process harness 验收。
- runtime 接收的类型已经满足 M0 invariant，不需要重复字符串/范围判断。
- operator 可以在目标平台 artifact 上做真正的离线 smoke。

### Negative

- strict unknown-field/canonical-base64 policy 不接受宽松但常见的输入。
- config error 共用 exit 2，调用者必须读取 stable code 才能细分。
- schema v1 的非 additive 变化需要显式 migration；M1 只能 additive 扩展 method/
  address support。

## Compatibility and upstream divergence

reference implementations 使用自己的 JSON schema；interop harness 运行时生成其
配置，不能把 reference schema 暴露为 ferrum2 operator contract。OS bind 检查不
属于 offline validation，这一点与 bootstrap roadmap 的早期模糊表述明确分离。

## Migration and rollback

这是首个 config schema，无旧配置迁移。M0 回滚只需回退 binary/config examples；
不得把 secret-bearing config 或真实 endpoint 提交。未来不兼容变更必须提高
`schema_version` 并提供新 ADR/spec。

## Verification plan

- M0-CFG-001：两端 valid matrix。
- M0-CFG-002：预占端口、recording connector 和 task registry 证明零副作用。
- M0-CFG-003：unknown/missing/range/method/base64/key/cross-field negative matrix。
- M0-CLI-001：help/version/exit/output contract。
- M0-PLAT-001～003：三个 artifact 的 valid/invalid offline smoke。

## References

- `AGENTS.md`
- `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`
- `docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md`
