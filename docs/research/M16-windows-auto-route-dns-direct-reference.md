# M16 Windows auto-route、DNS 与 direct outbound 参考基线

- **Status:** Planning research baseline
- **Date / access date:** 2026-08-10
- **Milestone:** M16
- **Scope:** IPv4-only Windows managed TUN 自动路由、socket 防回环、per-interface DNS、网络变化与新增
  client `direct` outbound；M15 manual-route IPv6 保持不变
- **Pinned upstream:**
  [`sing-box@411df0183a114a249eeeed8da029349ae0189b5c`](https://github.com/SagerNet/sing-box/commit/411df0183a114a249eeeed8da029349ae0189b5c)、
  [`sing-tun@909ab10ad507c93f3024554d6e6d1f81dd7aff0f`](https://github.com/SagerNet/sing-tun/commit/909ab10ad507c93f3024554d6e6d1f81dd7aff0f)、
  [`sing@59379fe7069c0f5bae69e2ff84e9c2fd4961a8af`](https://github.com/SagerNet/sing/commit/59379fe7069c0f5bae69e2ff84e9c2fd4961a8af)

## 结论

1. sing-box 证明 Windows auto-route 可以由 route prefix 集合、逐 socket interface pinning、
   per-interface DNS 和 route/interface notification 组合实现；它不是 Ferrum2 的所有权或清理合同。
2. sing-box Windows 默认 capture 是 IPv4/IPv6 `/0`，同时把 TUN interface metric 与 route metric
   都设为 `0`。Ferrum2 不应因此放弃已选择的兼容型 split `/1` 方案。
3. 新增 `[[outbounds]] type = "direct"` 后，物理目的地址来自每条已路由 TUN flow，不能像固定
   Shadowsocks server endpoint 一样在启动时枚举。每个 direct TCP/UDP socket 必须在
   connect/send 前，依据 **capture 前固定的物理接口策略**完成 pinning；否则该 socket 会再次命中
   capture route 并回到 TUN。
4. Windows per-interface DNS 只能称为 resolver steering。Windows 多宿主 resolver 会在首选 adapter
   未及时响应后查询其他 adapter；没有额外 enforcement 时不能声称 DNS 独占或 anti-leak。
5. `ActiveStore` 只表示重启后丢失，不表示进程退出自动删除。`TerminateProcess` 也不给 Rust owner、
   termination handler 或 DLL 正常清理机会；硬杀零残留必须由 VM 证据、外部 watchdog/service，或
   OS 对 owned ephemeral adapter 的级联删除合同承担。
6. Exact restored-VM preflight 只发现一个可用 IPv4 physical default，没有 IPv6 physical default、
   non-link-local physical IPv6 address 或 owned off-link dual-stack endpoint。这个结果只支持规划改界，
   不是 PASS，也不应把本地 identifier、address 或 credential 写入仓库。M16-new managed capture、DNS、
   pinning、change evidence 与 privileged qualification 因此改为 IPv4-only；M15 manual-route IPv6 adapter/
   transport、SIP022 IPv6 和 non-managed/SOCKS direct IPv6 不变。

## 1. sing-box Windows 行为

### 1.1 `/0`、metric 0 与 prefix subtraction

[`BuildAutoRouteRanges`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_rules.go#L109-L211)
在 Windows 的默认 auto-route 路径产生 `0.0.0.0/0` 和 `::/0`；存在 exclude 时，先把 include
prefix 加入 IP set，再 `RemovePrefix`，最后只返回 subtraction 后的 prefix 集合。它不为 exclude
另建 physical bypass route。

Windows configure 路径在 auto-route 下关闭 automatic metric，并把 IPv4/IPv6 TUN
[`MIB_IPINTERFACE_ROW.Metric` 设为 `0`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_windows.go#L123-L160)；
随后以 metric `0` 创建 route，并使用 TUN address 派生的 gateway 作为 next hop
([`Start`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_windows.go#L169-L187)、
[`addRouteList`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_windows.go#L600-L628))。

这只提供两项可复用结论：prefix subtraction 可行；route metric 与 interface metric 是不同量。
Ferrum2 的 next-hop、metric 和 split `/1` 必须按目标 Windows build 实测并 exact readback，不能从
sing-box 数值直接推导。

### 1.2 逐 socket interface pinning

sing-box 的默认 dialer 在 socket connect 前安装 interface control
([`default.go`](https://github.com/SagerNet/sing-box/blob/411df0183a114a249eeeed8da029349ae0189b5c/common/dialer/default.go#L71-L125)、
[`network.go`](https://github.com/SagerNet/sing-box/blob/411df0183a114a249eeeed8da029349ae0189b5c/route/network.go#L341-L370))。
Windows implementation 对 IPv4 使用 `IP_UNICAST_IF` 且把 interface index 转为 network byte
order；IPv6 使用 `IPV6_UNICAST_IF` 且保持 host byte order
([`bind_windows.go`](https://github.com/SagerNet/sing/blob/59379fe7069c0f5bae69e2ff84e9c2fd4961a8af/common/control/bind_windows.go#L12-L60))。
Microsoft 的 socket-option 合同也分别规定 IPv4 index 为
[network byte order](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options#options)，
IPv6 index 为
[host byte order](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options#options)。

Pinning 是 **socket 创建路径的属性**，不是给目标添加一条临时 bypass route；TCP 和 UDP 都必须走
同一个不可绕过的创建边界。

### 1.3 per-interface DNS、synthetic hijack 与 WFP strict 是三层不同机制

- `native`/`hijack` 都会在 auto-route 下调用 Wintun LUID 的 per-family
  [`SetDNS`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_windows.go#L73-L121)。
- `hijack` 额外从 TUN prefix 派生 synthetic DNS address，并在 TUN inbound 对该 address 的
  UDP/TCP flow 做 DNS 识别/接管
  ([`inbound.go`](https://github.com/SagerNet/sing-box/blob/411df0183a114a249eeeed8da029349ae0189b5c/protocol/tun/inbound.go#L331-L337)、
  [`JudgeFlow`](https://github.com/SagerNet/sing-box/blob/411df0183a114a249eeeed8da029349ae0189b5c/protocol/tun/inbound.go#L523-L583))。
- `strict_route` 是独立的 Windows WFP dynamic session；在 `hijack` mode 下还添加 off-TUN port 53
  block filters
  ([`tun_windows.go`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/tun_windows.go#L188-L368))。
  Microsoft 规定 dynamic WFP objects 随 session 结束自动删除
  ([WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management#sessions))。

因此，配置 Wintun DNS、synthetic DNS fast path 与 WFP enforcement 不能混称一个“DNS
ownership”能力。Ferrum2 M16 不引入 WFP 时，只能承诺已验证的 Wintun interface steering 与
synthetic destination handling。

### 1.4 网络变化通知

sing-tun Windows 同时注册 route-change 与 IP-interface-change callback
([`monitor_windows.go`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/monitor_windows.go#L23-L57))，
共享 monitor 以一秒 timer debounce 后重新计算 default interface
([`monitor_shared.go`](https://github.com/SagerNet/sing-tun/blob/909ab10ad507c93f3024554d6e6d1f81dd7aff0f/monitor_shared.go#L63-L103))。
底层 Windows 原语是
[`NotifyRouteChange2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)
、[`NotifyIpInterfaceChange`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)
和
[`NotifyUnicastIpAddressChange`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)。

通知只说明“应重新检查”，不能证明原 route/interface 仍可使用。Ferrum2 可采用更简单的合同：
检测到会改变已发布物理策略的事件后，停止新 flow、撤销 capture 并终止；不在 M16 实现 live-flow
migration。

## 2. Microsoft 路由与 DNS 合同修正

### 2.1 正确的 physical route 查询顺序

[`GetBestInterfaceEx`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex)
接收 IPv4/IPv6 destination 并返回当前 best-route interface index；
[`GetBestRoute2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)
则要求 `InterfaceLuid` 或 `InterfaceIndex` 至少一个已初始化，并输出 `MIB_IPFORWARD_ROW2` 与
`BestSourceAddress`。所以用于 capture 前 physical snapshot 的明确顺序是：

```text
GetBestInterfaceEx(destination)
  -> validate/convert interface index (and reject Wintun/loopback as policy requires)
  -> GetBestRoute2(interface, destination)
  -> freeze interface identity + best source + route fingerprint
```

不能把 `GetBestRoute2(destination)` 写成不带 interface 的 API。对 direct outbound，capture 生效后
再调用 `GetBestInterfaceEx(destination)` 也会观察到 capture 后的路由世界，因此不能恢复原 physical
选择；必须使用 capture 前发布的 immutable policy，并在每个 dynamic destination socket 创建时
据此选择/验证 interface。

### 2.2 `InitializeIpForwardEntry` 不会产生可直接创建的完整 row

Microsoft 要求在 `CreateIpForwardEntry2` 前调用
[`InitializeIpForwardEntry`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry)。
初始化结果是：`ValidLifetime`/`PreferredLifetime` 为 infinite，`Loopback`、
`AutoconfigureAddress`、`Publish`、`Immortal` 为 `TRUE`，`SitePrefixLength`、`Metric`、`Protocol`
为 illegal value，其余字段为零。Ferrum2 必须显式填写/覆盖自身合同要求的字段，不能把这些默认值
误当成安全 route policy。

[`CreateIpForwardEntry2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2)
至少要求有效 `DestinationPrefix`、`NextHop` 和 `InterfaceLuid`/`InterfaceIndex`；完整 route metric
是 row metric offset 与 interface metric 的和，`Age`/`Origin` 会被 stack 设置。创建前应拒绝
exact-owned-key 冲突，成功后以系统返回 row readback；rollback 只删除 journal 中成功创建且仍匹配
owned identity 的 rows。

### 2.3 per-interface DNS 不是独占解析

[`SetInterfaceDnsSettings`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings)
只设置给定 interface GUID 的 DNS settings；它并未赋予该 interface 全局独占权。Microsoft 的
[Windows DNS 查询顺序](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups#dns-client-service-resolver)
明确说明：resolver 先查询 preferred adapter 的首个 DNS server；一秒未响应后，会查询所有仍在
考虑中的 adapter。因此 M16 必须用正反 VM evidence 描述实际 steering，不能将其表述为对其他
interface、应用自带 DoH/DoQ 或任意 port 53 traffic 的阻断。

### 2.4 `TerminateProcess` 与 `ActiveStore` 的硬杀边界

[`TerminateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
无条件终止所有线程；Microsoft 另明确说明线程没有机会运行额外代码，attached DLL 也不收到 detach
通知
([Terminating a Process](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process))。
所以 `Drop`、`finally`、owner command 或普通 process shutdown hook 都不能证明硬杀 rollback。

[`New-NetRoute -PolicyStore`](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute?view=windowsserver2025-ps#-policystore)
把 `ActiveStore` 定义为当前 OS 使用、**重启后**丢失的 routing information；文档没有把 lifetime
绑定到创建进程。因此 ActiveStore route 不能靠进程死亡自动回收。计划中的硬杀验收必须外部观察
adapter、route 与 DNS residue，并在证据失败时停止，而不是把“非 persistent”误写成“process
scoped”。

## 3. Ferrum2 `direct` outbound 的新增约束

目标配置是：

```toml
[[outbounds]]
tag = "direct"
type = "direct"
```

路由规则选择该 action 后，TUN 中已接管的 TCP/UDP flow 应直连原 destination，不经过
Shadowsocks。与 concrete proxy outbound 不同，direct destination 在启动时未知。M16 的 Windows
TUN-selected direct 只给 IPv4 target 发布 physical binder；原 target 为 IPv6 时，不论
`auto_route` true/false，都必须在 physical socket 前 fail closed。SOCKS/non-Windows direct IPv6
保持。对 IPv4 而言，“只预先 pin 全部 proxy endpoint”仍不足以防回环。

M16 计划应冻结以下不变量：

1. 在添加任何 capture route 前，建立并发布可验证的 IPv4 physical-interface policy。M16 只选择
   一个 pre-capture IPv4 default；需要多宿主/目标特定 route 语义的 IPv4 prefix 必须 exclude。
2. 每次 IPv4 direct TCP connect、UDP association/socket、无 detour DNS bootstrap，以及 concrete
   proxy first-hop 的 socket 创建都经过同一 Windows binder；先设置 `IP_UNICAST_IF`，再 connect 或
   首次 send。IPv6 concrete proxy 或 direct/no-detour DNS physical endpoint 在 mutation 前拒绝；
   IPv4 proxy first hop 后的 logical IPv6 DNS bootstrap 仍可通过 tunnel 传递。
3. direct flow 的 route action snapshot 与 socket pin snapshot 都是 per-flow immutable；运行中 selector
   或网络状态变化不改写已建立 flow。
4. IPv4 route/interface/address notification 使 physical policy 失效时，先拒绝新 socket；M16 选择重新
   验证并原子发布，或撤销 capture 后终止。不得让新 direct socket 无 pin fallback。
5. VM A/B 必须使用 IPv4 物理默认路由可达的 owned off-link TCP/UDP target：unpinned negative control
   应重新进入 Wintun，pinned case 不得进入 Wintun；fixed proxy first-hop 与 dynamic direct 各覆盖
   TCP/UDP pinned/unpinned。Resolver 只需 IPv4 UDP/TCP 两行。既有 M15 `16/16` 继续覆盖 IPv6 回归，
   但不算 managed IPv6 proof。

### 3.1 M16 选择的有界 underlay 语义

M16 不复制完整的 capture 前逐目标 Windows route table。固定 IPv4 Shadowsocks first-hop 与物理 DNS
bootstrap 仍按各自 endpoint 冻结 exact physical interface；启动后才出现的 IPv4 direct target 统一
绑定到 capture 前选定的一个 IPv4 physical default interface。缺少该 interface、interface 失效或
binding 失败都使 selected flow 失败，绝不退回 unpinned socket。Reachable physical first hop 必须
resolve 为 IPv4；IPv6 concrete proxy/direct-no-detour DNS physical endpoint 在 validation/prepare 且
host mutation 前失败，logical IPv6 DNS bootstrap behind an IPv4 proxy first hop 则仍允许。

这个选择刻意不保持多网卡环境下每个目标原有的 LAN、企业 VPN 或非默认 interface 路由语义。需要
这些路径的 prefix 必须通过 `route_exclude_address` 留在 TUN 外。逐目标 physical route fidelity、
live underlay migration 和可配置 interface policy 留给后续独立决策。

同一 IPv4 dynamic-direct binder 也适用于 `auto_route = false` 的 Windows TUN+direct graph：产品在
Ready 前做只读 physical snapshot，M15 external controller 只能在 Ready 后添加 manual capture。这样
IPv4 direct 不依赖 controller 为任意目标枚举 physical bypass；Windows TUN-selected direct IPv6 在
socket 前失败；没有 direct 的 manual-route 配置仍保持 M15 exact，包括 IPv6 adapter/data plane。

## 4. 不复制 sing-box 的项目

- 不复制 Windows `/0 + interface metric 0 + route metric 0`；Ferrum2 使用自己的 split `/1` 与实测
  IPv4 metric/next-hop 合同，也不从 upstream dual-stack 行为推导 M16 managed IPv6 support。
- 不复制同名 adapter 创建失败后 `OpenAdapter`；Ferrum2 保持 exclusive owned adapter identity。
- 不复制 `DadTransmits = 0`；继续 session/media up 后等待自然 `Preferred`。
- 不复制更新时 `FlushRoutes(AF_UNSPEC)`；只删除 exact journaled rows。
- 不复制缺少 precheck、逐 row readback、partial-failure journal 与可报告 cleanup error 的 route owner。
- 不复制 WFP `strict_route`、off-TUN port 53 block 或 kill-switch 声明；若以后需要，单独做安全决策。
- 不复制 network-change 时 live connection/DNS/stack reset；M16 先采用可证明的撤销接管并终止。
- 不把 per-interface DNS 称为系统 DNS 独占，也不把 ActiveStore 称为 process-owned。

本文件固定的是规划事实和 stop conditions，不冻结 crate 拆分、trait 数量或 Win32 wrapper 文件树；
这些应由最小可验证实现决定。
