# M15 Wintun、smoltcp 与 Windows 网络接口上游基线

- **Status:** Planning research baseline
- **Date / access date:** 2026-08-09
- **Milestone:** M15
- **Scope:** Wintun `0.14.1`、`windows-sys 0.61.1`/`0.61.2`、smoltcp `0.12.0`/`0.13.1`、Rust `1.97.1`，以及 Windows interface address/MTU 的系统副作用

## 结论

M15 草案不能原样进入实现。上游核验给出四个需要先改计划的结论：

1. 官方 Wintun `0.14.1` ZIP、AMD64 DLL、签名和 ABI 均可固定；但 DLL 使用的是 ZIP
   内自定义 **Prebuilt Binaries License**，不是 MIT，也不是源码的 GPL-2.0。它能否与
   Ferrum2 的 `GPL-3.0-only` 分发方式兼容属于法律判断，本研究不能裁决，发布前必须取得明确结论。
2. 复用 lockfile 的 exact `windows-sys = 0.61.2`；M15 direct edge 明列八个 feature，并区分该声明与
   已由其他 workspace consumer 统一出来的更大 feature union。文件/目录与 CNG hash API 也必须由
   direct edge 声明，不能依赖 Tokio 等 consumer 的偶然 feature。
3. 用户最终选择 exact no-default `smoltcp 0.13.1` 与截至 2026-08-09 的 latest stable
   Rust `1.97.1`；第 7.2 节的 `0.12.0`/Rust `1.88.0` 只是已被最终裁决覆盖的历史 fallback。
   最终 feature 集合不启用正向 `auto-icmp-echo-reply`，仍把双向 TCP/UDP filter 与
   no-fragment 边界作为 owner 安全不变量；T03 将 workspace、CI 与 policy MSRV 从
   `1.88.0` 原子提升到 `1.97.1`。上游身份、exact feature 和后续更新控制见第 8 节。
4. “产品不调用 route API”可以成立；“添加 interface address 不产生 route row / Windows
   system mutation 不包括 route row”不能成立为计划保证。地址配置包含
   `OnLinkPrefixLength`，配置可产生由 Windows 管理的 connected/on-link/local route
   状态。M15 应只否认**显式创建及所有权**的 capture/default/bypass route，并把系统托管 route
   纳入前后快照和回滚验证。

## 1. Wintun 0.14.1 artifact、许可与 ABI

### 1.1 固定 artifact

[Wintun 官方下载页](https://www.wintun.net/)声明 `0.14.1` ZIP 的 SHA2-256 为：

```text
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
```

本机对用户提供的
`C:\Users\ZZZ\Downloads\wintun-0.14.1.zip` 独立计算得到相同值；校验通过后才解压。
ZIP 的完整 payload 是：

| Path | Bytes |
|---|---:|
| `wintun/LICENSE.txt` | 5,431 |
| `wintun/README.md` | 13,916 |
| `wintun/include/wintun.h` | 10,362 |
| `wintun/bin/amd64/wintun.dll` | 427,552 |
| `wintun/bin/x86/wintun.dll` | 550,928 |
| `wintun/bin/arm64/wintun.dll` | 222,488 |
| `wintun/bin/arm/wintun.dll` | 364,552 |

AMD64 DLL 的 SHA-256 是：

```text
e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
```

Windows `Get-AuthenticodeSignature` 在 2026-08-09 返回 `Valid`；signer 为 WireGuard LLC，
证书 thumbprint 为 `DF98E075A012ED8C86FBCF14854B8F9555CB3D45`，时间戳证书为
DigiCert Timestamp 2021。这确认了当前主机信任库下的签名状态；它不是对未来证书状态的保证。
PE 检查确认文件为 AMD64，并导出草案要求的 11 个 symbol；完整导出表还包含
`WintunOpenAdapter`、`WintunDeleteDriver` 和 `WintunSetLogger`。官方页也明确说明 ZIP 含四种
architecture 的 signed DLL 和 header。

因此 release ingestion 应同时固定 **ZIP hash 与所分发 AMD64 DLL hash**。仅在构建时核验 ZIP，
再在运行时按路径加载一个未核验 DLL，不能证明执行的仍是该 artifact。

### 1.2 许可裁决

官方页把[源码](https://git.zx2c4.com/wintun/)描述为 GPL-2.0，并说预编译 DLL 使用
[官方 ZIP](https://www.wintun.net/builds/wintun-0.14.1.zip) 内
“more permissive license”。实际 `LICENSE.txt` 名为 **Prebuilt Binaries License**：许可仅覆盖
该官方 ZIP 中精确的 `wintun.dll`，授予 non-exclusive、non-transferable 使用权；禁止逆向、修改，
但允许 DLL 与只通过随附 `wintun.h` API 使用它的其他软件一起分发。

所以“官方预编译 DLL 可随调用它的软件分发”得到文本支持；“许可证就是 MIT/开源许可证”是错误的。
该自定义条款与 Ferrum2 `GPL-3.0-only` 的组合分发兼容性、notice/offer 要求和安装包呈现方式均为
**undecidable here**，必须由项目的许可负责人或法律顾问确认后再把 artifact 进入 release。

### 1.3 ABI 和生命周期中必须写入计划的事实

精确来源为 Wintun tag [`0.14.1` / `bfef136abfa1665c2592be09a7e383d646cdbe6e`](https://git.zx2c4.com/wintun/commit/?id=bfef136abfa1665c2592be09a7e383d646cdbe6e)，
尤其是 [`api/wintun.h`](https://git.zx2c4.com/wintun/tree/api/wintun.h?h=0.14.1)、
[`api/session.c`](https://git.zx2c4.com/wintun/tree/api/session.c?h=0.14.1) 和
[`api/adapter.c`](https://git.zx2c4.com/wintun/tree/api/adapter.c?h=0.14.1)。

- 所有 function typedef 使用 `WINAPI`；Rust 动态 symbol 类型应是 `unsafe extern "system" fn`。
- null/zero sentinel 失败后必须立即读取 `GetLastError`。`WintunCloseAdapter`、
  `WintunEndSession`、`WintunReleaseReceivePacket` 和 `WintunSendPacket` 是 `void`，没有可读取的
  成功/失败返回值。
- ring capacity 是 `0x20000..=0x4000000`（128 KiB..=64 MiB）且必须为二次幂；session source
  实际分配 RX、TX 两个 ring，因此内存预算不能只计一个 `ring_capacity`。
- header 只规定 packet size `<= 0xffff`，没有规定最小值为 1；`1..=65535` 可以是 Ferrum2
  自己的有效 IP packet policy，不应写成 Wintun ABI 要求。
- RX pointer 在 `WintunReleaseReceivePacket` 前有效；send buffer 必须由
  `WintunSendPacket` 释放。allocation 顺序决定真实发送顺序。
- read event 属于 session，调用方不得 `CloseHandle`，且只应在 receive 返回
  `ERROR_NO_MORE_ITEMS` 后等待。source 创建的是 auto-reset event，并在 `WintunEndSession`
  中关闭；Microsoft 规定等待中的 handle 被关闭时行为未定义，因此 shutdown 必须先唤醒、停止并
  join waiter，再 end session。Wintun 没有 TX-ready event。
- header 说关闭 created adapter 会移除它；实现若 removal 失败只写内部 log，而
  `WintunCloseAdapter` 仍返回 `void`。草案又拒绝解析 `WintunSetLogger`，故“关闭后 adapter
  一定已删除且失败可报告”无法由 ABI 保证，只能用 privileged E2E 外部核验。

## 2. DLL 安全加载

Microsoft 的 [`LoadLibraryExW`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
文档确认：完整绝对路径只固定目标 DLL；dependency 搜索还由 flags 决定。M15 应：

1. 从实际 executable path 构造唯一 sibling `wintun.dll` 绝对路径，拒绝相对路径、CWD、PATH、
   user path 和 network path；
2. 以 `LOAD_LIBRARY_SEARCH_SYSTEM32` 限制 dependency 搜索。已核验 DLL 的 imports 全部是 Windows
   system DLL，因此没有理由允许任意 sibling dependency；若将来确有随附 dependency，才加入
   `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` 并重新审计；
3. 对 release/runtime DLL 执行上面的 exact hash policy；如最低版本允许，可附加
   `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET`，但签名有效不能替代 exact-version hash；
4. 用 [`GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
   按 exact case-sensitive name 解析全部必需 symbol，任一缺失即卸载并失败。

`LOAD_LIBRARY_SEARCH_*` 在 Windows 8+ 原生可用；Vista/7/Server 2008 系列需要 KB2533623，
`LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` 要求 Windows 8.1+。因此“安全加载”在未写最低 OS 时是不完整
的。M15 最简单且可验证的合同是 Windows 10/11 AMD64；若要支持更旧版本，必须显式 feature-detect
并 fail closed，不能降级到普通搜索。

绝对路径、search flags 与 hash 仍假定安装/executable directory 的 ACL 可信；当前计划没有给出
installer/ACL 合同，所以“攻击者不能替换 sibling DLL”不能仅由 loader API 证明。

## 3. `windows-sys 0.61.1` 可用性

精确 crate 元数据见 [`Cargo.toml.orig`](https://docs.rs/crate/windows-sys/0.61.1/source/Cargo.toml.orig)；
published crate 指向 windows-rs commit
[`aafae1f2d445b954f7032dcaf3bd702f85cf5899`](https://github.com/microsoft/windows-rs/tree/aafae1f2d445b954f7032dcaf3bd702f85cf5899/crates/libs/sys)。
它的 MSRV 是 `1.71`，license 是 `MIT OR Apache-2.0`，不会推动 M15 的 workspace MSRV。

结论是 **可以满足 M15**。精确 binding 中存在：

- `GetModuleFileNameW`、`LoadLibraryExW`、`GetProcAddress`、`FreeLibrary`；
- `CreateFileW`、`GetFileInformationByHandleEx`、reparse/file/directory flags；
- `BCryptHash` 与 built-in SHA-256 provider；
- `CreateEventW`、`SetEvent`、`ResetEvent`、`WaitForMultipleObjects`、`CloseHandle`；
- `ConvertInterfaceIndexToLuid` / `ConvertInterfaceLuidToIndex`；
- `Initialize` / `Create` / `Get` / `DeleteUnicastIpAddressEntry`；
- `InitializeIpInterfaceEntry`、`GetIpInterfaceEntry`、`SetIpInterfaceEntry`，以及
  `NET_LUID_LH`、`MIB_UNICASTIPADDRESS_ROW`、`MIB_IPINTERFACE_ROW`。

最小显式 Cargo feature 集合应包含：

```text
Win32_Foundation
Win32_Storage_FileSystem
Win32_System_LibraryLoader
Win32_System_Threading
Win32_Security_Cryptography
Win32_NetworkManagement_IpHelper
Win32_NetworkManagement_Ndis
Win32_Networking_WinSock
```

`Win32_Security_Cryptography` 会启用 parent `Win32_Security`；后者即使传 null security attributes
也需要，因为 `CreateEventW`/`CreateFileW` binding 本身受该 feature gate。generated binding 使用
`extern "system"`，但调用 Win32/Wintun、解引用 raw pointer
和把 `GetProcAddress` 结果转换为精确 function pointer 都仍需要项目自己的窄 `unsafe` exception。

这些 API 的存在不等于任意 Windows 版本都支持：IP Helper 的 LUID/address/MTU API 为 Vista+；
loader search flags 的更严格限制如上一节。crate 不做运行时 OS gate。

## 4. smoltcp `0.12.0` 与 `0.13.1`

结论基于 crates.io 发布包及其 exact
[`0.12.0 Cargo.toml.orig`](https://docs.rs/crate/smoltcp/0.12.0/source/Cargo.toml.orig) 和
[`0.13.1 Cargo.toml.orig`](https://docs.rs/crate/smoltcp/0.13.1/source/Cargo.toml.orig)。

| Fact | `0.12.0` | `0.13.1` | M15 impact |
|---|---|---|---|
| Rust version / edition | `1.80` / 2021 | `1.91` / 2024 | 草案的 `1.91` 只对 `0.13.1` 精确成立 |
| License | 0BSD | 0BSD | 两者相同；仍需纳入 dependency notice/audit |
| Published source identity | `d2d647090d544b1e7c142571da9d55f7280f664b`，metadata 标记 dirty | `e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897` | `0.12.0` 结论以 published crate 为准，不把 git commit 当作 byte-identical artifact |
| `medium-ip`, IPv4/IPv6, TCP/UDP, Reno、fragment/count features | 存在 | 存在 | 草案列出的这些 feature name 可解析 |
| Echo reply control | 无开关，IPv4/IPv6 echo reply 路径无条件编译 | 正向 `auto-icmp-echo-reply`，默认开启 | `default-features=false` 且不启用正向 feature 可在 `0.13.1` 关闭；不存在 `no-auto-*` |
| Unsafe policy | crate root `#![deny(unsafe_code)]`；可选 Unix host `phy::sys` 模块局部 allow/use unsafe | 同左 | 草案未启用 `phy-raw_socket`/`phy-tuntap_interface`，因此该可选 sys 路径不进入 M15 feature graph；不能把这表述成整个发布包“零 unsafe source” |

所以在“不 fork upstream、自动 echo 必须关闭”的前提下，选择 `0.13.1` 是合理的；若回退
`0.12.0` 只是为了保留 Rust 1.80，就必须另加 ingress ICMP 过滤或接受 echo 行为，这会改变 M15
合同。草案的 feature 列表应删除 `no-auto-icmp-echo-reply`，否则 Cargo 解析直接失败。

### 4.1 共同的功能边界

精确 `0.13.1` sources：[`phy::Medium/Device`](https://github.com/smoltcp-rs/smoltcp/blob/e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897/src/phy/mod.rs)、
[`Interface::set_any_ip`](https://github.com/smoltcp-rs/smoltcp/blob/e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897/src/iface/interface/mod.rs#L414-L422)、
[`fragmentation.rs`](https://github.com/smoltcp-rs/smoltcp/blob/e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897/src/iface/fragmentation.rs)；
`0.12.0` 在下列边界上相同。

- `Medium::Ip` 是正确选择：收发无 Ethernet header 的 IP frame，不使用 MAC，也不做 ARP/NDISC。
- public `set_any_ip` 文档要求 smoltcp **内部** route prefix 通过一个 interface `ip_addr`；但
  `0.13.1` 当前内部 `has_ip_addr` 在 `any_ip=true` 时直接返回 true。文档和实现不一致。计划不应
  靠未承诺的实现捷径；应显式配置 IPv4/IPv6 smoltcp route（这不是 Windows route），并为 route
  count 写测试。
- `Device` 的 Rx/Tx token GAT lifetime 绑定 `&mut Device`；Wintun RX pointer 不能跨 token、thread、
  await 或 channel。`TxToken::consume(len, closure)` 本身没有 fallible return，而且 `transmit()`
  事先不知道 `len`；所以“在 consume 前直接取得精确长度且保证成功的 Wintun send buffer”不是通用
  实现。应在返回 token 前保留有界 staging slot，ring full 时执行明确的有界 queue/drop policy。
- checksum capability 默认是 `Both`，会验证 RX 并生成 TX IPv4/TCP/UDP/ICMP checksum；IPv4 UDP
  checksum 为零是协议允许的例外，不能写成“每个 UDP packet 都有非零并通过验证的 checksum”。
- `fragmentation-buffer-size-65536` 是**出站 IPv4 fragmentation** buffer，不是 ingress
  reassembly 上限；`assembler-max-segment-count-32` 同时影响 packet reassembly 与 TCP
  out-of-order reassembly。
- 启用 `std` 会启用 `alloc`；此时 ingress `PacketAssembler` 使用 `Vec<u8>`，按网络提供的 total
  size 或 `offset + data.len()` 调用 `resize`，`reassembly-buffer-size-*` 静态数组上限不生效。
  `reassembly-buffer-count-4` 只限制并发 assembler 数量。因此若 M15 要求严格预分配/配置字节上限，
  当前 feature 组合不满足；必须增加 ingress prefilter 与可证明的 worst-case accounting，或改变
  alloc/上游实现策略。
- 尽管存在 `proto-ipv6-fragmentation` feature，普通 IP medium 的 exact source 没有 IPv6 fragment
  reassembly，egress 还明确记录 IPv6 fragmentation unimplemented 并 drop。草案“有界 IPv4/IPv6
  fragment reassembly”是错误的；M15 要么明确只支持 IPv4 fragment reassembly 并拒绝 IPv6
  fragments，要么更换/补丁实现并重新审计。
- 不启用 `auto-icmp-echo-reply` 只关闭 echo；stack 仍可能生成协议要求的 ICMP error（例如 UDP
  port unreachable）。这与“不提供 ICMP proxy socket”并不矛盾，但需要测试和 observability 合同。

## 5. Windows address、MTU 与 connected route

Microsoft 的
[`CreateUnicastIpAddressEntry`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry)
要求 address 与 LUID/index，并用 `OnLinkPrefixLength` 表示 IPv4 subnet mask / IPv6 link prefix。
官方 [Wintun example](https://git.zx2c4.com/wintun/tree/example/example.c?h=0.14.1)只调用该 API，设置
`10.6.7.7/24`，没有调用 route-creation API。

Windows API 文档没有承诺 `CreateUnicastIpAddressEntry` 的 route table diff 为零。相反，Windows
官方 route 示例会显示 interface address 对应的 subnet on-link route 和 local host route；例如
[Azure Windows route-table 示例](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
中，一个 `10.0.1.10/26` interface 同时出现 `10.0.1.0/26 On-link` 与本机 host row。由这些 primary
sources 可作出的保守推断是：配置 address/prefix 会让 TCP/IP stack 管理 connected/on-link/local
route 状态，即使应用从未调用 `CreateIpForwardEntry2`。

因此 M15 范围应改写为：

- 产品不调用 IP-forward/route mutation API，也不创建、不认领、不删除外部 capture/default/
  bypass route；
- 允许并记录由 Ferrum2-owned address/prefix 派生的 OS-managed route rows；删除 address/adapter 时
  由 OS 联动清理，Ferrum2 不单独删除这些 row；
- privileged E2E 在 add-address 前、ready 后、delete-address/close 后分别 snapshot route table，
  验证只出现预期的 connected/local rows，且最终归零。具体 row 集合/Origin 需用目标 Windows
  build 实测，不能从当前 API contract 静态决定。

这也意味着 `/30`、`/126` interface prefix 本身会对该小前缀形成 on-link 影响；“没有外部窄 route
就绝不会有任何流量进入 Wintun”过强。外部 route owner 仍只负责额外测试/capture 目标。

另外两项必须进入 activation/rollback：

- 新 address 在 duplicate-address detection 完成前不可用；文档给出 IPv6 通常约 1 秒、IPv4
  通常约 3 秒。`CreateUnicastIpAddressEntry` 成功不能立即触发 `tun_ready`，应轮询
  `GetUnicastIpAddressEntry` 至 `Preferred`，或明确限定 Windows 10+ optimistic DAD 行为。
- [`MIB_IPINTERFACE_ROW`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row)
  和 [`SetIpInterfaceEntry`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry)
  按 address family 工作。IPv4、IPv6 的 `NlMtu` 应分别 get/snapshot/set/restore；“一个 old MTU”不够。
  运行期间若第三方并发修改 MTU，API 没有 compare-and-swap，所谓精确 rollback 所有权仍是
  undecidable policy，计划应规定冲突时 fail/leave/report，而不是静默覆盖。

## 6. 计划必须修改的最小清单

1. 对 Wintun 同时固定 ZIP hash 和 AMD64 DLL hash；把 custom binary license 与 GPL-3.0-only
   兼容性设为 release 前置决定，而不是把它标成普通 permissive/MIT dependency。
2. 明确 Windows 10/11 AMD64 最低运行基线；写出 absolute-path、System32-only dependency search、
   exact hash、全部 symbol fail-closed 的 loader contract。
3. 复用 `windows-sys = 0.61.2`，加入上列八个 direct-edge feature，并记录窄 FFI unsafe exception。
4. 使用 exact no-default `smoltcp = 0.13.1`，不启用正向 `auto-icmp-echo-reply`；双向
   TCP/UDP filter 仍强制使 ICMP 路径不可达。
5. IPv4/IPv6 fragment 与 IPv6 extension 全部显式 reject；不启用或实现 reassembly。
6. 显式配置/测试 smoltcp 内部 AnyIP routes；与禁止 Windows route API 的 architecture test 分开。
7. 把 Windows route scope 改成“无显式/owned capture route”，并验证 OS-managed connected rows；
   ready gate 加 DAD，MTU ownership 分 IPv4/IPv6。
8. 对 Wintun close 的 silent adapter-removal failure 增加 E2E postcondition；不要把 RAII drop 描述成
   可报告的事务式删除保证。

## 7. Historical Addendum：复用 lockfile identity 并保留 Rust 1.88

本节保存当时选择 `smoltcp 0.12.0` 并保持 Rust `1.88.0` 的历史 fallback。
**第 8 节的 `smoltcp 0.13.1`/Rust `1.97.1` 最终选择已覆盖本节的 dependency/MSRV 裁决**；
前述 Wintun、`windows-sys 0.61.2`、许可、ABI 和行为事实保持有效。

### 7.1 复用 `windows-sys 0.61.2`

当前 `Cargo.lock` 已包含 registry `windows-sys 0.61.2`，checksum 为
`ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc`；本机从 crates.io
重新取得的发布包 hash 与之相同。精确
[`0.61.2 Cargo.toml.orig`](https://docs.rs/crate/windows-sys/0.61.2/source/Cargo.toml.orig)
仍声明 Rust `1.71`、edition 2021、`MIT OR Apache-2.0`，VCS identity 为
[`32c3144490c016fe496a0aed769bce60987a2e9d`](https://github.com/microsoft/windows-rs/tree/32c3144490c016fe496a0aed769bce60987a2e9d/crates/libs/sys)。

`0.61.2` 的 `LibraryLoader`、`Threading`、`IpHelper`、`Ndis` 四个 generated source 文件与
`0.61.1` 字节一致；第 3 节列出的 loader/event/LUID/address/MTU symbol、struct 均仍存在。
最终 held-path/CNG-hash contract 还需要 `Storage::FileSystem` 与 `Security::Cryptography`；因此 M15
应增加 exact、default-off direct edge `windows-sys = "=0.61.2"`，明列第 3 节的八个 feature 并复用现有
lock identity，不应为了已验证的相同 API 新增 `0.61.1` package identity。lockfile 中另有旧的
transitive `windows-sys 0.52.0`；M15 wrapper 不应误用该版本。

当前 workspace 的其他 consumer 已在同一 `0.61.2` identity 上统一出额外 feature。最终 gate 应
比较 M15 前后 inverse feature tree：直接 manifest 必须正好是上述八项，M15 引入的 resolved delta
不得越过这八项由 Cargo dependency 定义的 transitive feature closure；不能错误要求整个 pre-existing
union 只有八项。

### 7.2 `smoltcp 0.12.0`/Rust 1.88 的 superseded fallback

当前 workspace MSRV 是 Rust `1.88.0`。如果 M15 把以下两道 filter 固化为数据面安全边界：

1. Wintun ingress 在把 packet 暴露为 smoltcp `RxToken` **之前**，fail closed 丢弃所有非
   TCP/UDP L3 packet；
2. smoltcp `TxToken::consume` 完成后、调用 `WintunSendPacket` **之前**，再次丢弃所有非
   TCP/UDP output；

那么 `smoltcp 0.12.0` 无条件编译的 ICMPv4/ICMPv6 echo reply 分支没有可达 ingress，且 stack
因 UDP closed-port 等原因生成的 ICMP error 也不能越过 egress filter。在这个明确合同下，
**`0.12.0` 可以作为保留 Rust 1.88 的最小选择**：它声明 MSRV `1.80`、license 0BSD，所需
`Medium::Ip`、TCP/UDP 和 Reno feature 均存在；不需要提升全 workspace MSRV 到 1.91。

**最终 no-fragment 决策取代本 addendum 先前“可实现/约束 IPv4 fragment reassembly”的条件性
建议，也取代第 4.1、6 节中把 IPv4 reassembly 作为 M15 工作项的建议。** M15 不启用任何
fragmentation feature，不实现 IPv4 或 IPv6 reassembly：IPv4 在完成最小 header/declared-length
校验后，只要 `MF = 1` 或 fragment offset 非零就立即 drop；IPv6 base `Next Header` 只允许直接
TCP/UDP，任何 extension header（包括 Fragment）一律 drop，不遍历 extension chain。

已在 published `smoltcp 0.12.0` `Cargo.toml.orig` 逐项核验的最终 dependency 是：

```toml
smoltcp = { version = "=0.12.0", default-features = false, features = [
    "std",
    "medium-ip",
    "proto-ipv4",
    "proto-ipv6",
    "socket-tcp",
    "socket-tcp-reno",
    "socket-udp",
    "iface-max-addr-count-2",
    "iface-max-route-count-2",
    "assembler-max-segment-count-4",
] }
```

其中不存在草案的 `no-auto-icmp-echo-reply`，也刻意不含 `proto-ipv4-fragmentation`、
`proto-ipv6-fragmentation`、fragment/reassembly buffer/count feature。第 4.1 节的动态 packet
reassembly buffer 风险因此不进入最终 feature graph；AnyIP internal route contract、TX token
fallibility，以及 `assembler-max-segment-count-4` 对 TCP out-of-order reassembly 的上限仍必须保留。

接受 `0.12.0` 还必须满足以下验收条件：

- ingress/egress filter 是不可绕过的 owner invariant，不是可选优化；畸形 IP header、unknown
  protocol 和不支持的 extension chain 一律先 drop，且只记录低基数 counter；
- IPv4 `MF=1` 与任意 nonzero fragment offset、IPv6 Fragment header 和所有其他 IPv6 extension
  header 都必须在 smoltcp 前 drop；不得为识别其 inner protocol 而重组或遍历 extension chain；
- negative tests 覆盖 ICMPv4/ICMPv6 echo、UDP closed-port ICMP error、unknown protocol、IPv4
  first fragment (`MF=1`)、IPv4 nonzero offset、IPv6 Fragment/Hop-by-Hop，并从 Wintun TX 侧证明
  没有 fragment 或任何非 TCP/UDP packet 发出；
- 若未来允许任何 ICMP packet 进入 smoltcp，或允许 smoltcp 生成的 ICMP 离开 wrapper，
  `0.12.0` 就不再满足“禁自动 echo”合同；届时必须升级到 `0.13.1` 并不启用正向
  `auto-icmp-echo-reply`，或采用经审计的上游补丁。

当时的 fallback 选择为：复用 exact `windows-sys 0.61.2`；在上述双向 TCP/UDP filter 成为
SPEC/TEST 强制项且 no-fragment 合同成立的前提下，使用上列 exact `smoltcp 0.12.0`
feature set 并保持 workspace Rust `1.88.0`。该选择仅作为历史备选记录，不再是 M15 验收基线；
第 8 节的最终选择取代它。

### 7.3 最终 single-owner shutdown 顺序

第 1.3 节“先唤醒、停止并 join waiter，再 `WintunEndSession`”表达的是不得在仍有线程等待
session-owned read event 时关闭该 event 的不变量，不要求最终设计增加独立 waiter。M15 最终由
同一个 Stack Owner thread 独占 wait、receive、RX lifetime、session 和 cleanup 时，顺序应是：

```text
caller 设置 shutdown flag 并 signal 独立 stop event
 -> Stack Owner 从 WaitForMultipleObjects 返回
 -> Stack Owner 停止 wait/receive/poll，释放全部 outstanding RX 和 bounded pending TX
 -> Stack Owner 在本线程调用 WintunEndSession，完成其余 owned cleanup，然后退出
 -> caller 最后 join Stack Owner
```

caller 不得在 Stack Owner 仍可能 wait/receive 时并发调用 `WintunEndSession`，也不得为了满足
“先 join”而等待一个必须由自己执行 session cleanup 才能退出的 owner。只有替代设计真的存在一个
不拥有 session cleanup 的**独立 waiter thread** 时，才应先 signal/停止并 join 该 waiter，再由
session owner 调用 `WintunEndSession`。最终 single-owner 模型采用上面的 owner-cleanup-then-join
顺序。

### 7.4 最终 DLL 路径信任边界

第 2.2 节的 ACL 限制仍成立：Win32 没有从已验证 file handle 直接执行普通 DLL 的受支持
`LoadLibraryExW` 变体。最终合同因此明确把 current executable installation directory 作为可信本地
边界；能改写它的主体本来就能替换 executable，超出 M15 runtime loader 的威胁模型。

在该前提下 runtime 仍须关闭可避免的 race：拒绝 UNC/network path；从 fixed-volume root 到
executable directory 逐组件以 `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` 打开并
拒绝 reparse attribute；不以 `FILE_SHARE_DELETE` 分享并持有这些 directory handle；同样打开、检查、
持有 non-reparse `wintun.dll`，以 CNG SHA-256 对 held handle 的 exact bytes 做 hash，再在全部 handle
存活时用同一 absolute path 调 `LoadLibraryExW`。测试必须包含 symlink/junction/reparse 和 ancestor
path-retarget mutation。这样 held-handle 结论只在明确的 trusted-directory 前提下成立，不再无条件
声称单个 DLL handle 能阻止祖先路径改指。

## 8. 最终选择：exact `smoltcp 0.13.1` + Rust `1.97.1`

本节记录用户最终选择，并覆盖第 7.2 节的 `0.12.0`/Rust `1.88.0` 历史 fallback；
第 1～5 节与第 7.1、7.3、7.4 节的 Wintun、`windows-sys`、Windows 副作用和 owner 不变量不变。

### 8.1 Primary-source identity

截至 2026-08-09，Rust 官方[release 列表](https://blog.rust-lang.org/releases/)的最新条目是
2026-07-16 的 [Rust 1.97.1 发布公告](https://blog.rust-lang.org/2026/07/16/Rust-1.97.1/)；公告明确说
Rust team 已发布 `1.97.1` point release。当前 `rust-toolchain.toml` 已固定 `channel = "1.97.1"`；
本机 `rustc -Vv` 返回：

```text
rustc 1.97.1 (8bab26f4f 2026-07-14)
commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452
host: x86_64-pc-windows-msvc
release: 1.97.1
```

crates.io 发布包的 exact [`Cargo.toml.orig`](https://docs.rs/crate/smoltcp/0.13.1/source/Cargo.toml.orig)
和[normalized `Cargo.toml`](https://docs.rs/crate/smoltcp/0.13.1/source/Cargo.toml)声明 `smoltcp 0.13.1`、
edition 2024、`rust-version = "1.91"` 与 license `0BSD`；[published crate source](https://docs.rs/crate/smoltcp/0.13.1/source/)
中的 feature 定义与 manifest 一致。本机对
[`smoltcp 0.13.1` crates.io 发布包](https://crates.io/api/v1/crates/smoltcp/0.13.1/download)计算得到：

```text
SHA-256  5F73D40463BBA65EFC9ADC6370B56DF76D563CC46E2482BBA58351B4AFB7535E
```

该值与 crates.io [sparse index 的 `0.13.1` `cksum`](https://index.crates.io/sm/ol/smoltcp)
`5f73d40463bba65efc9adc6370b56df76d563cc46e2482bba58351b4afb7535e` 完全一致。M15 因此固定
registry 发布 artifact，不以可变 git branch 代替其身份。

### 8.2 Exact no-default feature set 与 packet boundary

最终 dependency 只使用以下 exact version 和十项 feature：

```toml
smoltcp = { version = "=0.13.1", default-features = false, features = [
    "std",
    "medium-ip",
    "proto-ipv4",
    "proto-ipv6",
    "socket-tcp",
    "socket-tcp-reno",
    "socket-udp",
    "iface-max-addr-count-2",
    "iface-max-route-count-2",
    "assembler-max-segment-count-4",
] }
```

published manifest 把 `auto-icmp-echo-reply` 定义为**正向** feature 并列入 default set。上述
`default-features = false` 且十项 allowlist 不含它；T03 的 resolved-feature gate 还必须证明同一
package identity 没有被其他 consumer 统一启用该 feature。列表也不含
`proto-ipv4-fragmentation`、`proto-ipv6-fragmentation` 或任何 fragment/reassembly buffer/count
feature。

升级不放宽 packet boundary：Wintun ingress 在暴露 `RxToken` 前只接受经完整校验的 bare-header
TCP/UDP；smoltcp output 在 `TxToken::consume` 后、`WintunSendPacket` 前再做同样的 TCP/UDP
filter。IPv4 `MF=1`/非零 offset 与 IPv6 的任何 extension/Fragment header 仍 fail closed drop，
不遍历、不重组、不发送。双向 filter 仍是 owner 安全不变量，不因上游已可关闭自动
echo 而降级为优化。

### 8.3 MSRV 与后续更新控制

`smoltcp 0.13.1` 自身的 MSRV 是 `1.91`，但 M15 选择当前 latest stable Rust `1.97.1` 作为
workspace 单一基线。`rust-toolchain.toml` 已是 `1.97.1`；T03 必须在同一受控变更中把
workspace manifest/MSRV 声明、CI MSRV job/commands 与 workspace policy/architecture assertions 从
`1.88.0` **原子提升**到 `1.97.1`，不允许一部分 gate 仍验收 `1.88.0` 或对应用不同
compiler 产生 split baseline。

以后任何 Rust toolchain/MSRV、`smoltcp` version、crate checksum 或上述 resolved feature 集合的更新，
都必须通过新的 reviewed control amendment 重新固定 primary-source identity、兼容性、packet/security
不变量和 CI 证据；不得把 floating `stable`、semver range 或 lockfile 的偶然变动当作已批准升级。
