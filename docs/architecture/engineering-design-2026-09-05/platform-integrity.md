# 平台完整性修复的最小实施边界

仅静态设计；没有生产修改、测试、编译、故障复现或网络操作。对接已选 NativeLifecycleOwner + 可关闭单槽 LifecycleLink；不引入 ManagedPlane / NetworkEpoch 整体 transition 重写。依据 platform.md PLAT-03–12、cross-check.md、当前源文件与根/TUN/platform/runtime AGENTS。以下接口形态为待实施设计，不声称已验证。

## PLAT-03/04：cleanup 结果贯穿局部事务

**seam 保持在已有平台 injected operations，TUN 只接收 CreateError。** 三处必须同时修改，否则任一处仍会丢失 cleanup 分类：

1. `windows/core/notification/mod.rs::subscribe_notification_sequence`：后续订阅失败时，继续逆序 cancel 所有已成功 handle；若任意 cancel 失败，保留现有故意泄留 handle/context 的安全行为，返回 `Error::cleanup()`，而不是原始 operation error。若全部取消成功，返回原始 operation error。不要为了可重试而释放仍可能被 callback 引用的 context。
2. `windows/live/wintun.rs::prepare_managed`：将成功订阅的 NotificationOwners 在 `snapshot_underlay` 之前放入 Adapter 拥有的 `pending_notifications: Option<NotificationOwners>`。当前完整 ManagedState 需要已完成 policy，不宜以虚假 policy 或大量 Option 字段提前构造。成功 snapshot 后，take pending owner 并移动到现有 ManagedState。`cleanup_inner`/`PlatformCleanup::cancel_notifications` 必须覆盖 pending 和 committed 两处，并保持最多一处持有的私有不变量；创建其他资源前发生的错误也进入现有 cleanup_transaction。这一个临时槽就是最小 staged transaction，不另建大模块。
3. `windows/core/managed/mod.rs::finish_setup_transaction`：保留 `Err(setup_error)`；无论它是否 cleanup-kind 都执行 outer cleanup，计算 `cleanup_failed = setup_error.kind() == Cleanup | outer_cleanup_failed`。用非短路步骤确保 outer cleanup 总被执行。strict-route-install 标志仍通过 `CreateError::strict_route_install(cleanup_failed)` 保留。TUN `owner.rs` 的 CreateError 分支先 cleanup_failed，再 cancel/deadline，再 retry；cleanup failure 一经观察为终止结果。

pending subscription 部分成功失败由 helper 负责，完整 subscription 但 snapshot 失败由 Adapter pending 槽负责。所有权转移不能中间 await，也不能在 take pending 后有可失败操作再交给 ManagedState。调用者显式 cleanup 才返回错误；Drop 的最后兜底不会被当成完整错误报告。通知关闭失败可能最终故意保留注册，不等于 use-after-free，也不能由最初 cleanup flag 推断全部后续重试后仍有实际残留。

既有 Production Adapter / injected fake operations 共同验证未来的 contract：订阅2/3失败×前序 cancel失败，snapshot失败×close失败，strict-route失败×cleanup失败，取消×上述组合；断言 CreateError 完整分类及逆序尝试所有 owned steps。单个纯判定测试不足以证明 staged owner 被 cleanup 看见。

## PLAT-05/06：读不到与确认损坏必须分开

保留公开 `managed_health() -> Result<ManagedTunHealth, Error>` 和 `revalidate_network_change() -> Result<NetworkChangeOutcome, Error>`。在 core managed 添加私有 `ReadbackMatch { Exact, Mismatch, Unavailable(Error) }`；本地 journal 存在性是确定状态，OS readback 是三态。比为所有调用者新增一个 public health 层更小。

- `managed_routes_match` 不再返回 bool；对每个 owned row：Absent/不匹配为 Mismatch；Failed 为 Unavailable。为保留 closed error 分类，可将原 `ManagedRouteRead::Failed` 改成 `Failed(Error)`，同样调整 AddressRead；各 live read Adapter 负责把 OS 结果变为 redacted 分类。明确的 ERROR_NOT_FOUND 是缺失，任意读取失败不能假装缺失。
- `managed_device_health` 改为 Result，并让 identity/address callbacks 返回三态。`managed_interface_identity_matches` 不再把 ConvertInterfaceLuidToIndex 失败压成 false；read_owned_address 的 health 路径复用现有 cleanup reader 的 Present/Absent/Failed 分类，避免 `.is_ok_and`。catalog `managed_tun().ok().flatten()` 也要拆开：锁/查询失败是 Error；成功返回 None 才是 ledger不符。内部 catalog/identity不变量损坏维持 terminal，不随便标记可恢复。
- 无法读取且可重试映射 `Error::recoverable_session()`；在 managed-health/revalidation 语境中 TUN 已把它映射 Retry / 轻量 ResetNetwork+settle，保留 adapter/session/journal。invalid/corruption/cleanup 仍精确映射 terminal。`revalidate_network_change` 当前 `Err(_) -> recoverable_session` 的 blanket 降级也要删除，传递已分类 Error。不要把 managed-read 的 RecoverableSession 交给包 I/O 的 `classify_adapter_error`，后者会触发 session rebuild。
- 已确认任一 damage 可以提前返回 Damaged；遇到 Unavailable 可以提前返回 Err 延后其余检查。该轮不能证明 Healthy，但无需全表扫描来找出所有损坏。只有一致的成功 readback 才更新 validated_generation/接受 policy；错误时保持 policy invalid/admission closed。

MTU 在现有 Adapter.mtus 两槽及 ManagedOwnershipLedgerView 的设备检查处添加完整性：启用IPv4/IPv6分别必须有对应family journal，禁用family不应有该槽，configured 必须等于已验证 config.mtu。journal 缺失/矛盾 → OwnershipLedger；成功读取 owned LUID/family 的 NlMtu 不等于 journal.configured → 新 `ManagedStateDamage::Mtu`；明确缺失对应 interface row → Mtu damage（或既有 Adapter damage，但选定后固定）；读取失败 → Unavailable。读取只查询本事务LUID，不查/修改物理接口。

新 Mtu damage 必须更新 platform 公共枚举、TUN `map_managed_state_damage`、TunNetworkFullRebuildReason、runtime ManagedNetworkDamage、client 映射、事件/指标闭集与 fixture 的所有穷尽 match。若这些层仅需泛化已有 `ManagedState` reason，则复用其明确语义，不能用 catch-all 隐藏遗漏。使用已有 MTU read/restore 所在 live managed 模块，只增加读函数与 injected read seam，不把 FFI 移入 core。未来 safe cases：IPv4/IPv6/dual-stack、缺槽、错family、不同MTU、not-found、transient读取失败；断言 retry 时 adapter identity/session 不变。

## PLAT-07/08：loader 局部修复

`PlatformLoader::verify_artifact` 首先判定 `metadata.len() == DLL_BYTES`，不等立即返回，不触碰body/hash。`cng_sha256` 保留同一个持有身份的 File，读取固定 DLL_BYTES 缓冲（427,552字节）用 `read_exact`，再仅读1字节验证EOF；不足或额外字节均失败。这样即使 metadata 与读取期间内容长度不一致，最多读 pinned-size+1，不再 unbounded read_to_end 或 Vec容量倍增。显式从文件起点读取（在同一文件句柄上 seek，或保证一次性新句柄读取契约）；不要重新按路径打开。固定常量转换用已证明界限，保留现有CNG hash、SHA256、精确ABI、held directories/file identity、System32加载与DLL pin行为。

`hold_directories`：CreateFileW 成功且不是 INVALID_HANDLE_VALUE 后立即 `let handle = DirectoryHandle(raw);`，再 `verify_directory_non_reparse(handle.0)?`，最终返回 owned handle。失败时当前handle与先前祖先集合自动Drop；保留原no-delete sharing。无需为这几行引入通用handle框架，也不扩大unsafe许可。未来针对验证失败的exact-once close应在已有loader injected seam/可替代owner支持下观察；不要创建真实目录破坏实验来验证。

## PLAT-09/11/12：明确而小的其余改动

AdapterConfig 六个pub字段改私有。保留 `new` 与 consuming `with_managed_network`，只为实际外部读取增加name借用及Copy标量getter；内部后代模块可读取祖先私有字段，无需每次内部访问机械改写。不给可变引用、不提供unchecked构造、不保留字段兼容层。当前构造器已有name UTF16<128/control检查、至少一family、MTU1280..1500、ring 131072..67108864且2幂、timeout1..60s；with_managed_network已有route/DNS family检查，这些保持平台唯一所有者。修改后成功构造值不能绕过后续family一致性。若未来增加setter，它必须重验managed关系；本次不需要setter。identity-bearing Debug 用redacted实现可与全局日志方案统一，不能凭现有Debug推断已有泄露日志。

PLAT-11只补已有trait与unsafe块文档，不加转发trait或lint抑制：SetupOperations说明每步成功/失败后journal责任；CleanupOperations说明逆序、继续尝试、取消通知context寿命、session idle前置；route/address读匹配说明unknown禁止delete；DNS apply说明成功后立即记录lease；notification wait说明generation/reset竞态；loader说明held identity；FFI局部说明指针长度/句柄唯一所有者/回调存活/EndSession不得与wait重叠。实现位置仍仅windows/live和已授权core/raw。

PLAT-12只改TUN `Stack::take_tcp_flow` 的free-list返还条件：recycle成功且`generations.current(slot).is_some()`才push（按GenerationTable实际slot参数类型使用）。与UDP退休逻辑一致；不要修改GenerationTable全局MAX语义，不扫描/重排全部free-list。未来注入近耗尽代数验证退休槽后仍可通过另一空闲槽admit，并保留旧handle stale；包热路径不增全表操作。

PLAT-10随NativeLifecycleOwner：准备时唯一absolute deadline必须包含Initialize callback及完成前检查；LifecycleLink关闭后Stopped优先释放等待再join。它不是Windows OS强制中断期限，不在平台重做timer。

## 选定 ordinary reset 的实施契约

当前顺序与TUN AGENTS有两处差异：`lifecycle/live/owner.rs:729–748`先cancel/quiesce/drop旧stack，下一轮`:539`才调用ResetNetwork；`runtime/reset.rs:708`先cancel_runtime_owners，`:733`先Stack hook，`:739`才publish，再运行其余hooks。此次按AGENTS改为publish→全部reset hooks→显式cancel→clear→replace；全局snapshot publication、TUN packet generation和UnderlayPublisher是三个不同状态，不能互相替代。

**采用native单次ResetNetwork请求；callback内执行publish→hooks(fence)→coordinator cancel/wait→hub retirement；native收到Completed再clear/replace。**保留现有LifecycleLink单次请求/回应与public hook协议。FullRebuild保留既有路径。

### 已确认 join 不等待 native quiesce

client/run/tun/root.rs中TCP注册TcpConnection，UDP注册UdpAssociation；两个handler最外层都select owner.cancelled与实际工作future。取消命中即drop实际工作与NetworkRuntimeOwner注册，无需run_tcp、UDP commit/receive自行完成。NetworkRuntimeOwner::drop只从coordinator映射移除并notify owner_changes。

TcpFlow::drop锁bridge、置aborted、signal work后返回，不等native。UdpCandidate/UdpAssociation::drop调用lease.close，只发送同步无界control notice，不等reply。即使commit future正在等待native oneshot，外层取消也会drop该future。ClientUdpAssociation::drop调用manager.remove并移除live id，socket字段正常drop。因此coordinator可以在native持有暂停旧stack时完成这些注册的取消。

**已进一步确认DNS idle pool也不要求native或pool.clear才能取消完成。**它的GenerationBoundUdpSocket在runtime/network_socket/generation.rs:322–349自带tokio monitor；monitor独立等待owner cancellation并close_generation_bound_udp_resource，即使idle wrapper从不poll，也会释放底层resource/registration。TCP wrapper有相同monitor。UDP进行中的send/recv通过select cancellation退出并drop借用的Arc resource；剩余最后一个resource Arc释放才注销owner。这是closed-resource所有权保证，不是coordinator仅看到某个标志就假装close完成。

该路径的全部注销动作独立于native packet loop。若应用自定义不可取消操作永久持有resource Arc，仍受已有callback/操作可取消契约约束；不以强制杀线程掩盖它。

### 选定 hooks 与 storage retirement 分工

现ClientEgressNetworkResetState::reset依次调用DNS actions（pool.reset：增generation并clear idle）和UdpSessionManager.reset_all（删除entries、发cancel、notify）。拆成client私有hub操作fence(g)、retire(g)、reopen(g)，按snapshot generation幂等；不将它们加入TUN公开接口。

- Stack/Router/Inbound hooks只接受已发布g；Stack文档改为接受新generation，不再承诺替换native stack。移除client“owner已构造新stack后才过桥”旧注释。
- Outbound hook运行hub.fence(g)：关闭UDP manager旧能力提交和DNS idle复用，不调用reset_all、不drop idle、不发送session/process cancellation。
- coordinator普通reset改为publish_snapshot(g)，执行Stack→Router→Outbound→Inbound，然后原顺序cancel_runtime_owners并等待。结束时仍按现有逻辑设置Active。
- client callback在coordinator.reset_network/retry_reset成功返回后**同步**hub.retire(g)，释放fenced manager entries、DNS idle缓存及其队列，然后hub.reopen(g)，最后向native返回Completed。两个hub操作之间不await。hub从fence到retire始终不接收新reserve/idle reuse，故coordinator短暂先Active不会让新manager资源混入旧cutoff。
- client shared network-change root也调用同一ClientNetworkResetRuntime的reset/retry逻辑。所有client driver方法用一个私有async mutex串行，锁覆盖coordinator调用和hub completion；不能有另一路reset插入coordinator成功与hub retirement之间。全仓搜索并收敛直接驱动调用，不把串行化留给调用者记忆。

coordinator hook失败时不执行正常retirement，保留同一g pending、closed fence，retry继续；强制停止是异常退出，可直接cancel/retire，不受正常hooks顺序约束。FullRebuild仍按原cancel/ManagedDamaged路径，hub的原完整reset可以作为fence+retire的私有组合；不改变native managed plane清理次序。

### UdpSessionManager的关联代数与network generation要分开

现SessionEntry.generation/UdpSessionHandle.generation是每manager关联唯一代数，next_generation在每次reserve递增；不是NetworkSnapshot.generation。当前reset_all物理删除entry才使matching_entry拒绝旧能力。

最小扩展是在SessionState增加reset: Option<{ network_generation, cutoff }>；cutoff为fence时next_generation，在原state mutex下设置，并关闭reserve准入。matching_entry/matching_entry_mut、retain_committed_handles、validate_direct_response及commit/pop/queue操作在原锁内拒绝generation<=cutoff，不新加hot-path锁，不重写handle代数。remove和PendingUdpSession/Datagram Drop使用“确切所有权匹配”，仍可回收fenced entry，不能使用“可用能力匹配”令旧storage无法清理。所有pending datagram rollback仍返还budget/queue数。

retire在同一锁下对cutoff内remaining entries执行原remove_entry，发cancel/notify、释放队列和guard，锁外publish_removal；reopen要求同一g已retired后清reset并允许reserve，但绝不清shutting_down。无需第二个retired表。fence按g幂等，hook retry不能重新捕获cutoff。自然drop可以先清理部分entry，retire不得重复计数。

这些是runtime通用UDP manager的命名生命周期方法，需要给既有client调用；它们不是新增TUN/LifecycleLink公开协议。迁移network-reset调用者，取消旧单步reset_all在这些调用处的使用；永久shutdown cancel_all/signal_all保持原职责。

DNS pool沿用generation/accepts_reuse：fence(g)关闭reuse并将pool本地generation递增一次；take_dns_udp关闭时失败，put拒绝旧generation；暂保留idle Vec。retire用mem::take取出idle，再锁外drop，避免持pool锁进入coordinator/manager锁。reopen仅在retired后开放reuse，generation耗尽永久fail closed。ClientDnsResetAction从一个Fn()->usize改为client私有的具名fence/retire/reopen动作容器，注册数仍有原界限8。指标保持原“pool缓存+manager remaining”计数语义，不能同时累计fence时所有entries和retire时remaining导致重复。

### TUN generation fence与清表的最小拆分

native退出active loop后关admitting，停止poll/flush/receive/owner commit，保留旧stack/session storage，执行Stack::fence_generation(next)。这一步只令旧外部能力失效：

- UDP将invalidate_session的session_epoch.store拆为fence_session(next)，不remove slot/clear response/reassembly、不发session cancel。native已暂停owner control/response处理，fence前已通过stale检查的竞态请求也不能被提交到新stack。晚到旧response保留到retire按原drop reason计数。
- UdpAssociation::receive目前只有receiver.recv，须在返回datagram前检查lease epoch；peer reservation commit/authorize复用现有stale检查并补齐遗漏。操作与fence重叠时按最后有效检查/原锁内提交线性化；不能承诺撤回已交给应用或OS的数据。新stack绝不复用旧control/response receiver。
- TCP不能仅mark_reset：现poll_read先pop缓冲后检查reset，仍能返回旧buffer。Bridge新增私有generation_valid，初始true；FlowOwner::fence在原mutex内置false并取wakers，释放锁后wake。poll_read在pop前检查valid，write/flush/shutdown把valid并入现reset判定。只增加原锁内bool分支，不加每包分配/锁。fence不清ByteQueue/socket/index。
- fence后native沿用adapter refresh_underlay并capture next snapshot；read Unavailable保持closed重试，确认damage才转原full rebuild。送出单次ResetNetwork后native仅等LifecycleLink回应，期间不驱动旧packet path。
- callback Completed后native才session_cancel_handle.cancel、Stack::retire_generation清旧TCP/UDP/provisional/packet/reassembly/channels，并drop旧stack，然后构造新stack。避免同时保留两个完整stack。新stack构造失败保留已发布同一g关闭并重试，不用g+1掩盖失败。最后验证underlay current，publish UnderlayPublisher并开放准入。

shutdown/full-rebuild的Stack::quiesce保留为fence+retire合成动作；ordinary拆开调用。retire检查同一已fenced generation，不重复改epoch/发reset metrics；generation溢出fail closed。应用因stale错误自然退出/Drop可早于显式cancel；契约不要求人为保留本可释放的资源。

### 最终顺序、joins与取消

1. native关准入、fence旧TUN能力、capture next snapshot，保留有界旧storage。
2. coordinator保持Resetting并publish_snapshot(g)；执行Stack→Router→Outbound(fence hub)→Inbound hooks。
3. coordinator按现有GenerationTask→TCP→UDP顺序signal/wait旧NetworkRuntimeOwner；handler取消和generation-bound socket monitors独立完成，无需native quiesce。
4. callback同步hub.retire/reopen，返回Completed。
5. native session cancel、clear旧stack/storage、构造新stack、generation/underlay检查、开准入。

coordinator证明旧NetworkRuntimeOwner注销；不能称所有Tokio JoinHandle已join。TunRoot现有JoinSet继续回收结束handler，关闭时abort/drain。generation socket monitor的现有生命周期不在此重构中改写；native join仍仅由NativeLifecycleOwner持有，所有准备/运行/rollback/Drop先关LifecycleLink再join。

publish后hook失败保留同一g pending，client不能再次require_next_generation拒绝已发布g，必须走retry_reset。同一g fence/retire记录使取消期future Drop后重试不重复计数。进程取消优先close LifecycleLink→Stopped唤醒native；client lifecycle guard记录并完成已经fenced hub的retirement，native自行cancel/clear/平台cleanup，不等callback ack。hub清理只是内存/owned socket Drop，不等待OS不可取消调用；cleanup完整性失败仍优先于正常取消。

唯一新增常驻代价是几个状态字段；现有线程、队列容量与消息往返次数保持。热路径新增TCP原mutex内valid检查和UDP manager原锁内cutoff判定；storage仍有原容量界限。这不是实测无回退结果，后续资格验证须比较CPU及reset latency。ring-full仍计数后丢包、不重试、不reset。

