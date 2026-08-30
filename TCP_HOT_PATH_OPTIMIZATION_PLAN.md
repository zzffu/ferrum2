# Ferrum2 非 TUN TCP 热路径优化计划与证据账本

状态：阶段 2、阶段 3 已完成实现与本地分轴测量；single-worker 产品候选
`d64b068a7f090a26313f8113590cf39be85f12b8` 在唯一一次真实 hosted direct CI 中达到
`62.9574%`，未达 90%。后续 two-worker、4+4 connection shard、2+2 balanced shard、
两代 incoming-CPU shard，以及两代 length→payload single-poll 候选均已提交、推送并判失败；
随后 fused decrypt-to-sink 候选在唯一正式本地样本中相对即时 `d874d3dd` 对照为 `+1.3604%`，
方向为正但幅度不足以触发 hosted direct CI；其 direct worker receive 与 worker-local out-of-place
open 两个子候选又分别相对父节点下降 `1.6963%` 与 `2.7589%`，均已判失败并冻结。独立 hot/cold
primitive 诊断证明 out-of-place AES-128 本身并不慢，因此不再把失败归因于 crypto primitive，也不为
单个未配对正式样本引入自研 GCM。阶段 3 的 copy-in 删除轴停止，`bf4cd4a6` 保持最后一个本地弱正向
节点。随后 generic relay 诊断取得 `+6.8394%` 方向性信号，但 fresh cross-frame next-length 两个产品
候选分别下降 `11.4717%` 和 `12.7505%`；one-shot retry 的恢复率为负，已确认整个 cross-frame
prefetch seam 有害并停止。fused progress stats 生命周期批量发布又下降 `2.0953%`，排除 per-write
方向 stats 原子是 generic 信号的主要来源。所有产品候选与诊断证据提交、远端分支均保留，90% 目标
随后 poll-local activity 候选再下降 `4.1066%`，说明 activity RMW/Notify 也不是主要瓶颈；90% 目标
仍未完成。

当前目标：在相同 hosted runner、相同 8-stream TCP lockstep workload 下，Ferrum2 吞吐量
达到 `shadowsocks-rust v1.24.0` 中位吞吐量的 **90% 以上**。

范围：Shadowsocks 2022 TCP、client/server 物理 TCP、公共 fused relay 和进程 runtime。

明确排除：所有 TUN 代码、TUN scheduler、Windows TUN adapter、route/DNS/WFP/Hyper-V
优化。本计划不受旧阶段 4—7 的编号约束；未达到 90% 前不宣告完成。

## 1. 权威 direct 基线

真实 GitHub Actions run `33233884631` 的 performance job 使用：

- Ubuntu 24.04 hosted runner，AMD EPYC 7763，4 vCPU；
- 8 streams，65,536-byte application payload；
- 每次 10 秒 warm-up、30 秒 measure；
- `F,R,R,F,F,R,R,F,F,R`，Ferrum/reference 各 5 次交错；
- reference 为已校验 archive 的 `shadowsocks-rust v1.24.0`。

结果：

| 实现 | 中位吞吐 |
| --- | ---: |
| Ferrum2 `4ba240c5` | 160,571,938 B/s |
| shadowsocks-rust v1.24.0 | 474,277,478 B/s |
| Ferrum/reference | 33.8561% |

90% 完成线按整数吞吐向上取整为 `426,849,731 B/s`。本地 Ferrum/Ferrum A/B 只用于筛选和根因定位；最终比例
只接受真实 hosted direct artifact，不使用伪造 `GITHUB_*` 环境的本地输出。

## 2. 解密失败契约

已删除“认证失败后原 ciphertext buffer 必须逐字节不变”的旧契约。保留它会强制 destructive
open 前复制完整 body，阻碍稳态热路径优化，而仓库内调用者在认证失败后都会 poison/终止 flow。

当前契约：

| 结果 | body/tag | nonce |
| --- | --- | --- |
| 成功 | 同一操作区得到已认证明文；tag 不发布 | 提交一次 |
| `AuthenticationFailed` | body destructive-clear，不发布候选明文；tag 可保留 | 不提交 |
| `NonceExhausted` | buffer 保持不变 | counter 保持不变 |

worker-local copyback 的普通路径可能让原 receive scratch 仍保留 ciphertext，但这是实现细节，不重新
升级为公共契约；重入 fallback 允许 primitive 直接清 body。

## 3. 分支纪律

所有候选均保留提交和远端分支。失败候选不删除、不 force-push、不回退；下一尝试从失败前的成功
公共基线另开 sibling branch。关键成功链及其后永久保留的 sibling 为：

```text
7edf4fcc  当前非 TUN 产品公共基线
└── 20c3883b  partial handshake I/O
    └── 790a0aa9  worker-local TCP copyback port
        └── d874d3dd  download carried continuation（后续 sibling 的共同基线）
            ├── 90dc643d → d64b068a  single-worker（direct CI 失败）
            ├── fd5a42de  bounded ready drain（失败）
            ├── 2e938fff  two-worker runtime（失败）
            ├── a1b67079 → 04a83c90  4+4 connection shards（双模态，失败）
            ├── 8ca007fd  2+2 balanced connection shards（失败）
            ├── ce8b2f10  server incoming-CPU pinned shards（本地 ratio 44.655%，失败）
            ├── 159928d3  dual incoming-CPU pinned shards（首样本 543.7 MB/s，失败）
            ├── 7e3f137a  length→payload single-poll（本地 -7.23%，失败）
            ├── 0ad5cab5  single-poll + transition Pending retry（即时对照 -0.90%，失败）
            └── bf4cd4a6  fused decrypt-to-sink（即时对照 +1.36%，弱正向、未进 CI）
                ├── 8fa19ec1  direct worker receive（相对父节点 -1.70%，失败）
                ├── bf516bb5  worker-local out-of-place open（相对父节点 -2.76%，失败）
                │   └── 7d06266c → 02b9faa4  hot/cold primitive diagnostic（diagnostic-only）
                ├── c84b5bc  generic relay diagnostic（相对父节点 +6.84%，diagnostic-only）
                ├── d27f96ce  fresh next-length continuation（相对父节点 -11.47%，失败）
                │   └── 27d98db4  Ready/Pending structural diagnostic（diagnostic-only）
                ├── c8537fce  fresh next-length + one-shot Pending retry（相对父节点 -12.75%，失败）
                ├── 54147afb  batched fused progress stats（相对父节点 -2.10%，失败）
                └── c0250248  poll-local activity reset（相对父节点 -4.11%，失败）
```

当前 CI 测量分支只在 `d64b068a` 上增加计划与证据绑定，不改变产品行为。

## 4. 阶段 2：删除发送整帧 memmove

产品路径已从 `64cd1410` 起采用 final-layout TX：

1. 先保留 encrypted-length 的 18-byte 最终区域；
2. transport 直接把 plaintext append 到最终 payload offset；
3. length body 与 payload body 分别原位 seal，再写 detached tag；
4. 不再为插入长度头对完整 payload 执行 `copy_within`/memmove。

wire vectors、0/1/边界 payload、nonce exhaustion 和稳态 allocation 测试覆盖该布局。

两个正式但失败的 Stage 2 同步测量候选仍保留：

- `codex/tcp-hot-path-stage2-headroom` @ `20063b11`；
- `codex/tcp-hot-path-stage2-final-layout-sync-measure` @ `e8f770f8`。

CI runs `33247994818`、`33249004750` 都在 candidate-only allocation gate 失败：首个 1-byte
case 在 hosted 环境记录 `4 allocations / 900 bytes / 128 frames`，而 Windows、WSL、Linux 本地
重复为 `0/0`。移除 Tokio runtime 不改变 hosted fingerprint，因此 Tokio 不是根因。失败分支保留，
但后续产品分支没有以其为祖先；final-layout 产品目标在当前公共线中独立存在。

## 5. 阶段 3A：partial I/O 正确性

分支 `codex/tcp-hot-path-stage3-partial-io`，提交 `20c3883b`。

实现：

- client request first-write 接受 short write 并累计 position；
- server request fixed region 接受 short read；
- client response fixed/payload 接受 short read；
- server first response 接受 staged short write；
- EOF、write-zero、partial-then-error 保持原 detection/transport 分类；
- 所有长度加法使用 checked arithmetic。

测试覆盖 1/7-byte progress、`Pending`、partial→error、exact wire、nonce 与 terminal。默认与
all-features tests、fmt、clippy 均通过。这是正确性提交，不把单次吞吐变化作为验收条件。

## 6. 阶段 3B：多 worker locality

分支 `codex/tcp-hot-path-stage3-locality-copyback-port`，提交 `790a0aa9`。

完整 payload 到达后同步执行：

```text
per-flow receive scratch
  → 当前 OS worker 的 Zeroizing staging
  → staging 内认证/解密
  → 成功后 copyback 到 flow scratch
  → 清 staging used range
```

TLS borrow 不跨 poll；重入退回 direct open；线程退出清完整 backing；18-byte length frame 保持
原路径；fused borrowed plaintext 仍指向 flow scratch。

本地 `profile-workload tcp-bulk`，8 streams，1 秒 warm-up、15 秒 active，ABBA：

| CPU affinity | parent | candidate | 变化 |
| --- | ---: | ---: | ---: |
| 1 CPU | 313,747,046 B/s | 286,470,963 B/s | -8.69% |
| 4 CPU | 145,070,490 B/s | 226,129,783 B/s | +55.88% |
| unrestricted | 140,629,333 B/s | 372,788,429 B/s | +165.09% |

因果形态明确：单 CPU 只有额外 copy/clear 成本；worker 数增加后，长期 receive scratch 的跨核
cache residency/migration 成本主导，worker-local mutation 恢复吞吐。

## 7. 阶段 3C：partial scheduling 消融

完整 one-shot 组合分支 `codex/tcp-hot-path-stage3-locality-one-shot` @ `dc5111d8` 保留，但相对
locality 的 30 秒 ABBA 为 `-1.90% / +0.36%`，总体约 `-0.77%`，没有可证明收益。

随后从 `790a0aa9` 独立拆分：

| 候选 | 提交 | 相对 locality |
| --- | --- | ---: |
| upload carried continuation | `30e088e2` | +1.64% |
| download carried continuation | `d874d3dd` | +5.33% |

选择 download-only：只有前一 poll 留下的 plaintext partial/Pending write 在本 poll 完整消费后，才
额外执行一次 fresh tunnel fill/write；之后仍强制 scheduling boundary。测试覆盖 sink
`Pending → external wake → Ready`、恰好一次 fresh fill、无重复/遗漏。upload-only 与 full-combined
均保留但不进入成功链。

## 8. 根因修复：单 Tokio worker

诊断分支 `90dc643d` 证明 client/server 各使用一个 Tokio worker 时，固定外部 4 CPU 的真实双代理
workload 大幅改善。产品提交 `d64b068a` 删除诊断 feature，正式 `run_prepared` 固定：

```text
Tokio multi-thread runtime
+ worker_threads(1)
+ enable_all()
```

materialize-only runtime 不变。代码未修改任何 TUN 文件。

固定 4 CPU、8 streams、15 秒 active 的 ABBA：

| runtime | bytes/s |
| --- | ---: |
| default Tokio worker count | 235,973,291 B/s |
| one worker per Ferrum process | 456,124,006 B/s |
| 变化 | +93.30% |

小请求 guard 同时改善：

| runtime | tcp-request-1k p99 | transactions/15s（约） |
| --- | ---: | ---: |
| default workers | 296 µs | 59.5k |
| one worker | 259 µs | 72.2k |

10k scale 诊断保持 `10,000 sessions`、`1,000 partial flows`、drain/rebind PASS；但 bytes 从
22.00 GB 降至 13.73 GB，Jain fairness 从 0.993 降至 0.973。这是明确 trade-off：当前目标选择
8-stream bulk 和 request p99，极高并发吞吐需要未来独立的 connection-sharded runtimes，而不是
重新允许一个 Send connection future 在普通 Tokio workers 间迁移。

## 9. 保留的失败/未选候选

| 分支/提交 | 结果 | 决定 |
| --- | --- | --- |
| release parity `ea05b3e5` | -5.81%；fat LTO/CGU1/panic-abort 单轴均负 | 保留，不采用 |
| RustCrypto VAES256 `d797b91d` | +0.49%，噪声级 | 保留，不采用 |
| ring persistent `e6edf7e3` | unrestricted -46.83%，1 CPU +53.12% | diagnostic-only |
| locality + ring `928366ed` | 4 CPU -51.7% | 保留，不采用 |
| ring per-operation rekey `7d4e14a3` | 4 CPU -47.5%，1 CPU +39.4% | 保留，不做 key cache |
| single-worker + ring `ef5d6df1` | 4 CPU 约 -95.7% | 非零化诊断，绝不产品化 |
| frame65535 build axis | 当前组合约 -69.4% | 65,536 workload 形成 65,535+1 tiny tail |
| single-worker direct-open `dfa12a66` | 4 CPU 约 -95.9% | copyback 仍是必需 |
| single-worker production `d64b068a` | direct CI 为 reference 的 62.9574% | 改善旧基线但未达目标；保留，不作为后续祖先 |
| bounded ready-read drain `fd5a42de` | 固定 4 CPU -6.15%；固定 1 CPU +0.95% | 多 worker 负载均衡退化；保留失败分支 |

ring 反汇编确认实际命中 VAES/AVX2，不是 fallback，也没有 payload copy/allocation。它只在整个拓扑
固定到同一 CPU 时快；普通 4-CPU affinity 允许 OS thread migration 后严重退化。除非未来有独立、
跨平台、可审计的 worker-thread affinity 设计，否则不 vendor/patch ring。

## 10. 正确性与质量 gate

已运行的核心 gate：

```text
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-shadowsocks --all-features --locked
cargo clippy -p ferrum2-crypto -p ferrum2-shadowsocks --all-targets --all-features --locked -- -D warnings
cargo test -p ferrum2-client --all-features --no-run --locked
cargo test -p ferrum2-server --all-features --no-run --locked
cargo fmt --all -- --check
```

single-worker production的 runtime 行为测试明确断言 runtime flavor 仍为 multi-thread 且 worker 数为 1。
client 完整 suite 的两个既有失败已在父提交独立复现：一个 TUN config Syntax、一个 UDP activation
timeout；二者不属于本次非 TUN TCP 范围。server 68/68 通过，client 116 个相关测试通过。

## 11. 唯一一次真实 CI 测量

[GitHub Actions run `33260356423`](https://github.com/zzffu/ferrum2/actions/runs/33260356423)
的 performance job 成功完成，且没有重复 dispatch：

- 测量 commit：`aca84fdcd4e44b779ddf7ee84bdaeb525e6d2fa7`；产品祖先为 `d64b068a`；
- Ubuntu 24.04 image `20260823.283.1`，Intel Xeon Platinum 8370C，4 vCPU；
- 8 streams，65,536-byte lockstep，10 秒 warm-up、30 秒 measure；
- `F,R,R,F,F,R,R,F,F,R`，Ferrum/reference 各 5 次；
- artifact ID `9717616894`，服务端 digest
  `sha256:3b7545914b0eab3212766e8f5ec66f940349ac90cc0ef3a041ade0c3942ca930`；
- `throughput.jsonl` SHA-256
  `43a7887bc6b52233e8a546bee7cdad11a0f9ae09a0b96f58cbac62fc8e6c81b4`；
- `binaries.sha256` SHA-256
  `59d6f1c6899dd5b7de1fe13de98e76adde1f7676d7e4f15ed4a79a198cd694b6`。

被测二进制在 throughput 前记录、之后由 `sha256sum --check` 全部复核成功：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `1e3d52b6cd10ff7e21c781f54dddf7b6c63209eef17f0f3585c1458a67de54fe` |
| `ferrum2-client` | `0525c9f1cd9e2646bf4d0f58ae25e02b308a8ac921fa5f5e27c81184556766d0` |
| `ferrum2-server` | `72b6cf492a0b45635de91bac3f177782b04e8a7729c871c1331b9b7f1e680567` |
| `sslocal` | `eec6d0ef06742c2bf7a592c756a9c7fab0a4f822bec8552679751142917ff332` |
| `ssserver` | `bbb26b41ad6ef40fd9a9ab399009ddff14ec22b1a04b77288671d9fa50dd9b06` |

原始 trial：

| trial | topology | bytes/s |
| ---: | --- | ---: |
| 1 | Ferrum | 430,634,871 |
| 2 | reference | 684,010,154 |
| 3 | reference | 681,264,196 |
| 4 | Ferrum | 427,950,080 |
| 5 | Ferrum | 430,960,366 |
| 6 | reference | 685,524,036 |
| 7 | reference | 683,852,868 |
| 8 | Ferrum | 430,551,859 |
| 9 | Ferrum | 434,147,601 |
| 10 | reference | 684,726,681 |

| 汇总 | bytes/s |
| --- | ---: |
| Ferrum 中位数 | 430,634,871 |
| shadowsocks-rust 中位数 | 684,010,154 |
| 90% 同轮完成线 | 615,609,139 |
| Ferrum/reference | **62.9573799%** |

结论：正确性、二进制身份和 performance artifact 完整，但绝对目标失败。Ferrum 还需要相对当前
提升 `42.95%`（`184,974,268 B/s`），差 `27.04` 个百分点。不得把本次结果解释成通过，也不得
为挑选样本重复 dispatch。

## 12. CI 后根因与新尝试

`d64b068a` 通过每进程单 Tokio worker 阻止 Send connection future 在 runtime workers 间迁移，
但同轮 reference 使用默认 multi-thread runtime，可利用 4 vCPU；8 条流因此变成 Ferrum 每个代理进程
最多一核、reference 多核，解释了剩余并行度缺口。

从 `d874d3dd` 开出的独立 `fd5a42de` 删除 subsequent RX 每次成功 read 的强制 yield，并使用现有
`64 ready I/O / 256 KiB / 8 frames` budget。同一候选固定 1 CPU 为 `+0.95%`，固定 4 CPU 为
`-6.15%`。这证明 same-poll 推进本身能省调度，但普通 multi-worker 依赖 frame 边界进行重任务
负载均衡；直接把 length 与 payload decrypt 绑定到当前 worker 会让 8 条流分配不均。

### 12.1 two-worker 与稳定连接 shard

`codex/tcp-hot-path-stage3-two-worker-runtime` @ `2e938fff` 从 `d874d3dd` 独立开始。固定 4 CPU
本地吞吐相对 `d874d3dd` 约 `+7.5%`，但远低于 single-worker 和 direct 90% 所需容量，因此判失败并
永久保留。

随后 sibling `codex/tcp-hot-path-stage3-connection-shards` @ `a1b67079`、`04a83c90` 使用中央 accept、
每连接固定 current-thread runtime、全局 permit-before-accept 和原 supervisor `JoinSet::spawn_on`
精确 owner/reap。Linux 4 CPU 下 client/server 各 4 shard。正确性、panic、forced abort/reap、M0、
fmt 和 clippy 均通过，但吞吐出现整轮双模态：

- 15 秒高档约 `0.965—1.037 GB/s`，30 秒高档 `1.044—1.061 GB/s`；
- 15 秒低档曾为 `442.6 MB/s`，30 秒低档 `486.3 MB/s`；
- 额外 ready 后探针抓到更严重低档：`143.4 MB/s`。

高档探针为 `1.028 GB/s`、8 shard 合计 `44.41 CPU-s / 14s`、`719` 次迁移；严重低档为
`143.4 MB/s`、`9.71 CPU-s / 14s`、`15,420` 次迁移。低档相对高档：总 shard CPU 时间减少
`78.1%`，migrations/CPU-s 从 `16.2` 增至 `1,588`，每 CPU-s 产出也下降约 `36%`。这排除了
固定约 15 GB、nonce、frame counter 或 buffer 容量阈值，证明低档是 active 调度迁移/convoy。
因为同一提交能达到超过 direct 90% 线的上包络，却不能可靠复现，该分支判失败且不触发 CI。

### 12.2 2+2 shard 证伪

`codex/tcp-hot-path-stage3-balanced-connection-shards` @ `8ca007fd` 再从 `d874d3dd` 独立开始，
只把两端 shard 数限制为 `min(available_parallelism, 2, max_connections)`。候选在测量前已提交并推送；
首个固定 4 CPU、15 秒正式本地样本仅 `395.3 MB/s`，合计 `22.63 shard CPU-s / 14s`，发生
`17,771` 次迁移，即 `785 migrations/CPU-s`，低于 `615,609,139 B/s` direct 完成线，立即判失败。

外部硬 affinity 继续证伪“零迁移即可解决”：

| 拓扑 | 吞吐 | active migrations | 结论 |
| --- | ---: | ---: | --- |
| client 2 shard 在 CPU 0/1，server 2 shard 在 CPU 2/3 | 145.5 MB/s | 0 | 全部连接边跨 CPU，convoy |
| client/server 各 4 shard，同 index 固定同 CPU | 151.3 MB/s | 0 | 独立 accept RR 并未形成真实同核连接对 |
| client/server 各 2 shard，双方都限制到 CPU 0/1 | 432.4 MB/s | 0 | 两核满载，但容量约等于 single-worker 档 |
| `d874d3dd` 普通 Tokio workers 逐线程硬 pin | 208.0 MB/s | 0 | 固定 worker 会破坏有益的动态 wake placement |

因此根因不只是 OS thread 迁移，而是两端独立 RR 形成随机、长寿命的 client-shard ↔ server-shard
连接图。少量动态迁移可追随 socket wakeup；失控迁移会崩到低档；盲目硬 pin 则可能把坏图永久固定。

### 12.3 server incoming-CPU sibling：配对成立但仍失败

`codex/tcp-hot-path-stage3-incoming-cpu-shards` @ `ce8b2f10` 从 `d874d3dd` 开始，不继承上述失败提交。
Linux 每个 current-thread shard 固定到进程 allowed mask 中一个 CPU；client 仍 RR，
server accept 后读取 accepted socket 的 `SO_INCOMING_CPU`，把连接投递到该 CPU 对应的 shard，不再使用
独立 RR。loopback 上 client shard 发起 connect 的 CPU 可直接协调 server shard；真实网络上则保持
server 本地 RX locality。Linux 枚举、pin 或 readback 失败必须闭合；Windows、UDP、TUN 保持
`d874d3dd` 路径。实现通过 Linux/Windows 编译、runtime/server tests、client compile-only、三包 clippy、
fmt 与 diff 检查，并在测量前提交、推送。

首个固定 4 CPU、3 秒预热 + 15 秒正式样本为 `539,265,160 B/s`；client/server 各四个 shard 的
affinity 均为 singleton，连接线程迁移为 0，Jain 分别为 `0.9902 / 0.9889`。同命令、同二进制的后续
预声明诊断 baseline 为 `744,038,946 B/s`，证明不是固定算力上限，但也证明首个低样本未被消除。
把 server shard 从 CPU `N` 外部改绑到 `(N+1)%4` 后，单次样本降至 `69,057,467 B/s`，全机 busy
从约 `77.15%` 降至 `9.34%`；因此 client ↔ server 同 CPU 配对是必要 locality，而不是导致串行空洞。

为避免把上一台 GHA 的绝对 `615,609,139 B/s` 误用于本机，另执行一次本机、同 invocation、固定
`F,R,R,F,F,R,R,F,F,R` 的 5+5 release 对照；它使用官方 shadowsocks-rust v1.24.0、共同继承
`taskset 0-3`，只作为 WSL 诊断，不作为 hosted 证据：

| topology | 五次 B/s（按执行顺序） | median |
|---|---|---:|
| Ferrum2 | 414,266,163; 464,772,573; 397,615,650; 357,227,997; 353,293,653 | 397,615,650 |
| shadowsocks-rust | 873,867,946; 895,348,462; 878,505,710; 890,415,786; 917,379,481 | 890,415,786 |

本地 ratio 为 `0.446550540`，远低于 90%，所以 `ce8b2f10` 正式判失败并冻结，不触发 CI。

### 12.4 双入口 incoming-CPU sibling：单变量无收益

`codex/tcp-hot-path-stage3-dual-incoming-cpu-shards` @ `159928d3` 直接从 `d874d3dd` 开始；
`ce8b2f10` 不是其祖先。它无提交地重建已审查的 pinned shard/server hint 逻辑，再增加一个单变量：
Linux client SOCKS accept 也读取 `SO_INCOMING_CPU` 并精确选择对应 shard；查询失败、`u32::MAX` 或
CPU 不在 pool 时仍共享 RR fallback。这样由 source 的初始 RX CPU 选择 client shard，client 在该 CPU
发起 tunnel connect，server 再按自己的 incoming CPU 选择同核 shard，闭合
`source → client → server` 初始 CPU 链。Windows、UDP、TUN 继续保持 `d874d3dd` 路径。

实现通过 Linux/Windows compile、runtime/server tests、client compile-only、三包 clippy、fmt、diff，
以及 Linux M0 `local_e2e` 6/6；在测量前提交、推送。唯一首个固定 4 CPU、3 秒预热 + 15 秒样本为
`543,747,822 B/s`，与 server-only incoming-CPU 的首样本 `539,265,160 B/s` 实质相同：client/server
各四个连接线程仍是 singleton affinity、迁移为 0，连接线程合计 `30.09 CPU-s / 14s`；三进程合计
`36.87 CPU-s / 14s`，四核容量占用 `65.85%`，runner 发生 `42,315` 次迁移。双入口单变量没有消除
低档，因此该提交判失败、冻结且不触发 CI。

### 12.5 length 完成后只 poll payload 一次（失败、冻结）

候选 `codex/tcp-hot-path-stage3-length-payload-poll` @ `7e3f137a` 直接从 `d874d3dd` 开始，不继承任何 shard
失败提交。根因假设是当前 receive 状态机即使已经完整读取并认证 18-byte encrypted length，也无条件
`wake_by_ref + Pending`；若 payload 已在同一 socket ready 批次中，这会为每个 frame 强制增加一次
Tokio run-queue 往返。64 KiB lockstep、双向、8 流会放大该等待空档，而 dual 候选仅约 66% 全机 busy
与调度等待相符。

候选只允许一个额外动作：length 在本次 poll 完成后，紧接着 poll payload 一次。payload Pending 依赖
底层注册的 waker；partial Ready 只 self-wake 并返回 Pending，不继续读；完整非空 payload 返回 plaintext；
完整零长度 payload self-wake 回 length 状态，不读取下一 frame。禁止循环、禁止跨 frame、禁止复用
`fd5a42de` 的 64-ready-I/O/8-frame/256-KiB budget。EOF、transport/protocol/auth 分类、nonce 提交、
失败不发布 plaintext 以及 destructive decrypt 契约保持不变。

实现通过 Shadowsocks all-features、Clippy、client/server all-features check、fmt、diff 以及独立审查，
并在测量前提交、推送。唯一固定 4 CPU、3 秒预热 + 15 秒正式样本为 `218,916,454 B/s`；相对
同配置 `d874d3dd` 历史值 `235,973,291 B/s` 下降 `17,056,837 B/s`（`-7.2283%`）。被测 SHA 为
`7e3f137ae8a72bc1a3f68f82e2e4555ac985a067`，tree 为 `a479ec9492fa153a75201e61424f3df0631ce5e7`；
client/server 二进制 SHA-256 分别为
`13ade9fca4fe3a0046e723c87c82afdf283ae64e0d27cc40beb759045a5d08a3` 和
`2697b8ed90b3dd82ac10be09bd730517899ca74adf6b47f2c423692d1bddcd18`。

14 秒 active 观测中 client/server 只消耗 `20.32 CPU-s`（平均 `1.451` 核），却发生 `91,950`
次迁移和 `426,279` 次 context switch，约为 `4,525 migrations/proxy-CPU-s`；全机平均 busy 仅
`40.779%`。这排除 CPU/AEAD 持续饱和，但不能单独证明 connection future 迁移：这里的 migration
计数来自 `/proc/<pid>/task/<tid>/sched`，度量 OS worker thread 跨 CPU，context switch 也不能区分
reactor wake 与 self-wake。该提交永久冻结、不触发 CI；前两次 probe 启动尝试均在创建代理进程前被
Git-worktree/M4 binary-dir 预检拒绝，正式 workload 的样本数仍严格为一。

随后对 `d874d3dd` 执行且只执行一次相同 3+15 秒探针对照：`231,232,853 B/s`、client/server
`23.12 CPU-s / 14s`（平均 `1.651` 核）、`133,942` migrations、`515,157` context switches、全机
`47.268%` busy。按这次相邻诊断对照，`7e3f137a` 吞吐为 `-5.3264%`，代理 CPU 为 `-12.1107%`，
migrations 为 `-31.3509%`，context switches 为 `-17.2526%`，busy 低 `6.489` 个百分点。候选没有
增加迁移或切换，反而以更少调度开销获得更高 bytes/proxy-CPU-s，却无法维持足够 runnable work；
“reactor wake 导致更多迁移/cache ownership”因此被否定。剩余根因是 length 公平 yield 被删除后
pipeline 填充不足，或 ready/partial payload 的 read + AEAD + 双 copy 被绑定在同一 outer poll 后造成
多 worker 公平性/convoy；这与 `fd5a42de` 固定 4 CPU `-6.15%` 的历史形态一致。

### 12.6 ready fast path + Pending scheduler retry（失败、冻结）

`codex/tcp-hot-path-stage3-length-payload-local-retry` @ `0ad5cab5` 重新直接从 `d874d3dd` 开始，不继承
`7e3f137a`。它作为区分 wake 来源的窄消融，保留 length 完成后只尝试一次 payload；若 payload 已 ready，
同 poll 完成并删除一次调度往返；若该首次 payload poll 返回 Pending，则恢复一次 synthetic
self-wake，使任务通常进入当前 worker 本地 FIFO 尾，但 Tokio 允许 steal，因此不承诺同线程/同核。
以后从既有 Payload 状态再次得到 Pending 时只依赖 transport waker，避免 busy loop。partial Ready、
zero frame、EOF/error/auth、nonce、terminal、不发布失败 plaintext、无循环和不跨 frame 契约均保持。
`d874d3dd` 同探针对照已经证明 OS scheduler migration/context-switch 指标没有恶化。该 sibling 仅
用于最后区分“首次 payload 真正 Pending 时缺一次 retry”是否解释 CPU occupancy 缺口。

实现和独立审查覆盖 transition 首次/后续两次 Pending、ready、partial、zero、EOF、transport/auth、
fused carried 上界，并在测量前提交、推送。唯一固定 4 CPU、3 秒预热 + 15 秒正式样本为
`229,144,439 B/s`；被测 SHA 为 `0ad5cab5e45b2e7c44dd0711f3c10f436b3f1652`，tree 为
`e6e35e55d87a3906752e1af404a91aafcaec15a6`，client/server 二进制 SHA-256 分别为
`4145cd71ba47c441b92d3dea07097220a76ba0666ec3375bc33686bd6190f499` 和
`f71ad328119eacc028edd386f8fb5804ad662304a850fd84b070e4a60abbc058`。

它相对 `7e3f137a` 回升 `10,227,985 B/s`（`+4.6721%`），恢复 single-poll 原始回归缺口的
`83.0436%`；代理 CPU 同时上升 `3.7894%`。这支持 transition Pending 的 scheduler retry 是主要
回归来源，而不是 migration/cache ownership 增加。但它仍比即时 `d874d3dd` 对照低 `2,088,414 B/s`
（`-0.9032%`），代理 CPU 低 `8.7803%`，migrations 低 `28.7684%`，context switches 低
`14.1130%`。按预声明停止条件判失败、冻结且不触发 CI；length→payload same-poll/wake 细调永久停止。

### 12.7 下一 sibling：保留公平点，减少 receive 数据搬运

下一尝试仍直接从 `d874d3dd` 开始，完整保留每帧 length 后的 scheduling boundary。候选只能减少
payload decrypt 周围的 worker-local copy-in/copyback/zeroize 或等价 transport 数据搬运，不能再次
合并 length→payload poll，不能继承 `7e3f137a`/`0ad5cab5`，不能扩大到 initial payload、TUN、
Windows/SOCKS 锁或 runtime shard。

Design It Twice 比较了三个 interface：最小 fused hook、通用 `AuthenticatedRx + Consumer` 深模块、
以及为常见 fused caller 定制的 forwarding seam。长期通用模块 depth 最高，但会同时重写普通 read、
buffered view、client/server/fused，无法保持单变量。本轮选择私有 `FusedProtocolFlow` seam，分支
`codex/tcp-hot-path-stage3-fused-decrypt-forward` 直接从 `d874d3dd` 创建；公共
`PlainBufferedDuplex` interface 和非 fused adapter 不变。

稳态 payload 在 worker-local staging 中认证成功后、zeroize 前直接 poll 真实 plain socket：full write
立即转回 Length，删除完整 TLS→flow-scratch copyback；partial 只 materialize 未写 suffix；Pending、
write-zero/error 为保持既有状态而 materialize 全量。sink 只在认证成功后可见明文，auth failure 不调用
sink、不提交 nonce并安装原 terminal；TLS borrow 不跨 poll。client initial response、TLS reentrant fallback、
多跳 buffered path 继续走 `d874d3dd` 实现。历史 `c24f512d` 只把 TLS plaintext 写到旧 generic relay
destination，之后仍需 socket write；当前 fused 下直接 poll 真实 sink 尚未尝试，因此是独立机制。

### 12.8 fused decrypt-to-sink 唯一正式样本

候选 `codex/tcp-hot-path-stage3-fused-decrypt-forward` @
`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a` 已提交并推送；tree 为
`4fcf9a25c47e251eb42aa24f8a6eb62fa1d702c0`。它直接继承 `d874d3dd`，`7e3f137a` 与
`0ad5cab5` 均不是祖先。最终生产差异仅为 `flow/io.rs` 与 `flow/fused.rs`，另有
`tests/tcp_fused.rs` 机制覆盖；没有 TUN、runtime、initial payload 或公共
`PlainBufferedDuplex` interface 改动。

独立复核为零 blocker。Shadowsocks all-features 全套、`tcp_fused` 15/15、no-default check、
client/server all-features check、all-targets/all-features Clippy `-D warnings`、fmt 与 diff-check
全部通过。测试明确覆盖 full/Pending/partial、write-zero/error/oversize、认证失败不 poll sink、
zero frame、client initial response，以及 TLS reentrant buffered fallback。

被忽略的一次性 probe 在 clean、pushed HEAD 上强制重建候选自己的 `target/profiling` 二进制，
固定 CPU 0—3，执行一次且仅一次 3 秒预热 + 15 秒正式 `tcp-bulk` workload；没有重跑或样本选择。
合同输出 `status=PASS`、`sample_count=1`、`runner_exit_status=0`、8 workers、53,645 transactions、
3,515,678,720 checked bytes，即 `234,378,581 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `b4179196ab6d832265e43756a7c6cb22698be28a7ae0f818111390aed9220377` |
| `ferrum2-client` | `696b21f3070047970b4127a5c73f8c47587a5d232b157ffaf25dfa09ea06ce22` |
| `ferrum2-server` | `8719df9278ce089a582fb087f72f876368bfc862179b93016c780f8a826f0711` |

同探针即时 `d874d3dd` 对照为 `231,232,853 B/s`，所以候选增加 `3,145,728 B/s`
（`+1.3604%`）。代理 14 秒 CPU 从 `23,120 ms` 增至 `23,180 ms`（`+0.2595%`），
每代理 CPU 的吞吐效率约提高 `1.0981%`；migrations 从 `133,942` 降至 `123,973`
（`-7.4428%`），context switches 从 `515,157` 降至 `505,073`（`-1.9575%`），平均 CPU busy
从 `47.268%` 变为 `47.156%`（`-0.112` 个百分点）。

结果方向为正，因此不按“性能更差”处理，也不回退该提交；但 `+1.36%` 与历史本地短样本波动量级
相近，并且不足以改变 direct 90% 判断，故该分支作为弱正向证据保留、暂不触发第二次 hosted CI。
它说明完整 TLS→flow-scratch copyback 具有可测成本，但不是当前主瓶颈：代理 CPU/CPU busy 几乎不变，
迁移下降也没有转化为同量级吞吐。下一候选应单独处理仍存在的 flow-scratch→worker-local copy-in，
同时继续保留 length 后公平边界、TLS borrow 不跨 poll 和失败明文不发布契约。

### 12.9 下一 sibling：direct worker receive

针对剩余 copy-in 比较两个独立 interface。方案 A 恢复 out-of-place AEAD，把完整 flow-scratch
ciphertext 直接解到 worker-local plaintext；它适用于所有 fragmentation，但需要重新扩展
`ferrum2-crypto` 与 vendored cipher API，而且历史 `160e0f19` 的相近 out-of-place 路径在 4 CPU
下降 `6.97%`。方案 B 仅在 fused payload 的首次 read 直接使用当前 worker 的 TLS staging；一次 read
完整时原位认证并沿 `bf4cd4a6` 的 sink seam 发布，Pending/partial/reentrant 则立即回落现有 scratch
状态机。方案 B 不改 crypto primitive、普通 buffered path 或 length 调度边界，故先选择方案 B。

分支 `codex/tcp-hot-path-stage3-direct-worker-receive` 从 `bf4cd4a6` 新建，以便候选 diff 和正式结果
只归因于“删除 flow-scratch→worker-local copy-in”。这只是实验 parent，不把单样本 `+1.36%` 的
`bf4cd4a6` 升格为已证实产品基线；判定时同时比较 `bf4cd4a6` 的 `234,378,581 B/s` 与共同基线
`d874d3dd` 的 `231,232,853 B/s`。若新候选不超过 `bf4cd4a6`，提交与分支永久保留，后续不从该
失败链叠加，而回到 `d874d3dd` 开 sibling。

TLS helper 必须支持动态 clear prefix：transport Pending 正常出口清 0 字节，partial 清实际读入前缀，
full/auth/sink 与 transport error 清完整 exposed range，unwind 保守清完整 range；旧 helper 继续全量
清理。任何返回前都释放 TLS borrow。合法超大 peer frame、普通 `poll_data_fill`、client initial
response、multi-hop fallback、TUN/runtime/Windows/SOCKS 均保持现状。

### 12.10 direct worker receive 唯一正式样本与失败判定

候选 `codex/tcp-hot-path-stage3-direct-worker-receive` @
`8fa19ec1d0f174804f42e7e9daa482e4c2cc940f` 已在测量前提交并推送；tree 为
`c41c4a633761a626235d100ebf53c909f4af845e`。它的 parent 为 `bf4cd4a6`，旧失败提交
`7e3f137a` 与 `0ad5cab5` 均不是祖先。独立终审为零 blocker；Shadowsocks all-features 全套、
`tcp_fused` 21/21、no-default、client/server all-features、Clippy `-D warnings`、fmt 与 diff-check
全部通过。

clean、pushed HEAD 的候选专属 profiling 二进制执行一次且仅一次 CPU 0—3、3 秒预热 + 15 秒正式
`tcp-bulk` workload；合同为 `status=PASS`、`sample_count=1`、`runner_exit_status=0`、8 workers、
52,735 transactions、3,456,040,960 checked bytes，即 `230,402,730 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `64047c25a0139d8e815254910b2557cfb99b04a4229d37f72bc7ab2b8b450346` |
| `ferrum2-client` | `df75f7239588f5523abbac722b2d1f6e892e729920d4d502d1419c2c7cf0ef83` |
| `ferrum2-server` | `f8e4ea20717b05c301004c9459471619dc281edf119a0da01c1ab638adef7f0d` |

相对父候选 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `3,975,851 B/s`（`-1.6963%`）；代理
14 秒 CPU 从 `23,180 ms` 降至 `22,890 ms`（`-1.2511%`），migrations 从 `123,973` 增至
`127,914`（`+3.1789%`），context switches 从 `505,073` 增至 `506,455`（`+0.2736%`），
mean CPU busy 从 `47.156%` 降至 `46.612%`（`-0.544` 个百分点）。相对共同基线
`d874d3dd` 也低 `830,123 B/s`（`-0.3590%`）。

按预声明的“不得低于父候选”条件立即判失败并冻结，不触发 CI、不重跑、不在 `8fa19ec1` 上叠加。
CPU 与 busy 同时下降而不是上升，说明失败不像算力过载；当前最可信假设是完整 direct read 命中率不足，
而每次 payload Pending 的提前 TLS/`RefCell` 借用、partial 的 TLS→scratch materialize 与前缀清零
降低 runnable progress。现有 probe 没有分支计数，这一因果尚未闭合；下一步先在独立诊断分支记录
full/Pending/partial/reentrant 次数，再从 `bf4cd4a6` 或共同基线开新的产品 sibling，绝不修改失败分支。

### 12.11 exact-binary uprobe 根因诊断

没有修改或重建 `8fa19ec1`。诊断直接绑定正式样本的 client/server SHA-256 与 DWARF/反汇编地址，
在两端分别对 direct helper entry、reentrant、Pending、partial、full，以及 sink delivery/materialize
设置 uprobe。PIE 的 RX LOAD 映射均为 `file offset = virtual address - 0x1000`；每个 outcome probe
都落在反汇编确认的独占 branch landing，结束后 probe group 已清理。

首次诊断启动在任何代理创建前被 M4 参数合同拒绝：`active=5` 小于允许下限，14 个计数均为 0；
因此 workload 未启动、诊断样本未消耗。修正为合同允许的 3 秒预热 + 10 秒 active 后只执行一次，
输出明确标记 `performance_authoritative=false`、`performance_adoption_allowed=false`；其吞吐不得用于
任何候选排名。workload 合同 PASS，41,184 transactions、2,699,034,624 bytes、8 workers、drain/rebind
均 PASS。

计数结果：

| 角色 | attempts | reentrant | Pending | partial | full | sink delivery | sink materialize |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| client | 107,439 | 0 | 0 | 0 | 107,439 | 107,439 | 0 |
| server | 107,447 | 0 | 0 | 0 | 107,447 | 107,447 | 0 |

两端 `attempts = reentrant + Pending + partial + full` 精确闭合；首次成功 direct read 的 full share
均为 `100%`，每帧额外 Pending 压力为 `0`，sink non-full/materialize 比例也为 `0`。高频 uprobe
会改变绝对调度，因而不能用本轮吞吐；但在合计 214,886 个 direct frames 中没有一次 fallback，
足以证伪“正式回归主要来自 Pending/partial/sink materialize”的假设。

根因因此收窄到 full-only direct path 本身，而不是命中率：Tokio 的 `poll_read_buf` 与
`poll_read_initialized` 最终进入同一 `TcpStream::poll_read_priv → PollEvented → recv`，差异不在系统
调用次数。`8fa19ec1` 把 TLS `RefCell` lease、动态 clear guard 和更大的分支状态机提前跨在 socket poll
周围，并删除了原 scratch→TLS 顺序 copy 的缓存预热；这组 full-path layout/locality 变化没有产生收益，
反而降低 runnable throughput。当前证据不能再细分“长 live range/指令布局”与“copy prefetch”各自占比，
但已足够判定“直接把 socket receive 搬进 TLS”不是可用解法。

下一产品 sibling 不继承 `8fa19ec1`：从 `bf4cd4a6` 开始，保留原 scratch receive、所有 fragmentation
与调度行为，只在完整 frame 后借 TLS；用 portable out-of-place AEAD 将只读 scratch ciphertext 直接
解到 worker-local plaintext，再沿 bf4 sink seam 发布。这样完全删除 8fa 的长 TLS-around-I/O scope，
同时继续独立验证删除 copy-in 是否有价值。

### 12.12 worker-local out-of-place open 唯一正式样本与失败判定

候选 `codex/tcp-hot-path-stage3-worker-local-out-of-place-open` @
`bf516bb58657a5d6827d2153b8c9d86a8c677cb9` 已在测量前提交并推送；tree 为
`d5bab0f2c7afbdf09ea1a54b5c9061e0a88235a6`。它直接从 `bf4cd4a6` 开始，`8fa19ec1` 不是祖先。
生产差异严格限于四个 crypto/vendor 文件、`flow/io.rs` 与 `tests/tcp_fused.rs`；没有 direct receive、
runtime、initial payload、Windows/SOCKS、TUN 或公共 `PlainBufferedDuplex` 改动。

完整 payload 仍先由原 flow scratch 收齐；随后才借 worker TLS，把只读 ciphertext-and-tag 直接解到
exact-size worker plaintext，再沿 bf4 sink seam 发布。三种 cipher 都使用 RustCrypto separate
`InOutBuf`，成功路径没有 scratch→TLS copy-in。新增 `TcpOpener::open_slice_into` 返回 `Result<()>`，
不返回冗余长度：认证或长度失败清完整候选 output、nonce 不提交；nonce exhaustion 在触碰 input/output
前失败；成功只提交一次 nonce。这里明确删除历史“失败时 output 原样不变”契约，不做 rollback copy；
只读 input 因接口结构保持不变，但这不是通过成功路径备份换来的兼容承诺。

两轮独立审查均为零 blocker。Crypto 全套 36 项、Shadowsocks all-features 全套、`tcp_fused` 16/16、
`tcp_fragmentation` 17/17、no-default check、client/server all-features check、两 crate all-targets/
all-features Clippy `-D warnings`、fmt 与 diff-check 全部通过。测试覆盖三算法成功/tamper/长度/nonce
exhaustion、auth failure 不 poll sink、fragmented transport 在完整 ciphertext 前不发布、sink
full/Pending/partial/error、zero frame 与 TLS reentrant fallback。

clean、pushed HEAD 的候选专属 profiling 二进制固定 CPU 0—3，执行一次且仅一次 3 秒预热 + 15 秒
正式 `tcp-bulk`；前面的 shell pipe 启动尝试因 `git.exe` 消耗脚本 stdin 在任何 build/proxy/workload
前静默结束，不消耗样本。改用 process substitution 后的唯一 workload 合同为 `status=PASS`、
`sample_count=1`、`runner_exit_status=0`、8 workers、52,165 transactions、3,418,685,440 checked
bytes，即 `227,912,362 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `8cc10e6ab28178853a0f3f11b3382fd26da5afbdeeead78769f12b6faa0e144a` |
| `ferrum2-client` | `02539403914066cdf3e086d0ef937f15b8f7ca134c173c23359f3ca92999eb98` |
| `ferrum2-server` | `4e0f75ae714ef41338c3abc92ae469bd50e59fe09d6d57383a14999b4893cad0` |

相对父节点 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `6,466,219 B/s`（`-2.7589%`）；代理
CPU 从 `23,180 ms` 变为 `23,160 ms`（`-0.0863%`），吞吐/代理 CPU 下降 `2.6749%`；migrations
从 `123,973` 增至 `130,836`（`+5.5359%`），context switches 从 `505,073` 增至 `512,254`
（`+1.4218%`），mean CPU busy 从 `47.156%` 变为 `47.045%`（`-0.111` 个百分点）。相对共同
基线 `d874d3dd` 则低 `3,320,491 B/s`（`-1.4360%`），CPU 高 `0.1730%`，效率低 `1.6062%`。

按预声明的“不得低于父候选”条件，`bf516bb` 判失败、冻结、不触发 CI、不重跑，也不作为后续产品
祖先。该判定是候选选择规则，不把单个未配对 15 秒差值自动升级为已证明的代码因果。

### 12.13 hot/cold primitive 诊断与根因边界

诊断分支 `codex/tcp-hot-path-stage3-crypto-open-micro-diagnostic` 只为同时调用两种 primitive 而从
`bf516bb` 开始；它是 diagnostic-only，绝不作为产品祖先。`7d06266c` 加入固定 CPU 2、32 KiB、
9 个 ABBA/BAAB 样本的 hot-source 测试；`02b9faa4` 继续加入 AES-128 cold-source 测试。两个提交均
已推送，既有 hot 测试没有为 cold 结果重写或重跑。

hot-source 中位数：

| cipher | copy + in-place | out-of-place | out-of-place 变化 |
| --- | ---: | ---: | ---: |
| AES-128-GCM | 10,543.5 ns/op | 10,164.8 ns/op | `-3.593%` |
| AES-256-GCM | 11,476.7 ns/op | 11,253.1 ns/op | `-1.949%` |
| ChaCha20-Poly1305 | 16,119.6 ns/op | 15,717.7 ns/op | `-2.493%` |

cold-source 只测正式 workload 使用的 AES-128：每个 role 使用独立 64 MiB ciphertext corpus 与
64 MiB eviction buffer，每个 timed role 前先驱逐 LLC、再预触热固定 output；2,048 个唯一 32 KiB
块/批，每样本两批、9 个平衡样本，只运行一次。copy + in-place 为 `12,074.8 ns/op`，out-of-place
为 `10,861.5 ns/op`，后者快 `10.048%`；九个 paired delta 均为负，范围 `-8.996%` 至
`-11.068%`，认证、完整明文和 checksum 合同全部通过。

因此可以排除以下产品回归解释：out-of-place primitive 算术本身更慢、`InOutBuf` 隐藏整帧 copy、
成功路径为失败输出契约做 rollback、普通 cold source 的第二遍读取是主要瓶颈。hot/cold micro 都与
产品样本方向相反。剩余解释只包括 micro 未模拟的跨核 dirty-line ownership/真实 socket 调度耦合、
少量集成 code layout，以及不可从一个未配对正式样本消除的运行波动。历史多 worker locality 消融和
本次 migrations/context-switch 方向支持前两项，但没有一项被当前证据单独闭合；特别是 `bf516bb`
相对共同基线只低 `1.4360%`，与 `bf4cd4a6` 的 `+1.3604%` 都处于历史短样本噪声量级。

### 12.14 阶段 3 停止决定

buffer rotation 方案曾从 `bf4cd4a6` 建立 clean 本地 lineage 分支
`codex/tcp-hot-path-stage3-worker-buffer-rotation`，但在任何代码、提交或 workload 前被审查否决：
交换 `BytesMut` owner 不迁移 cache line，却会破坏固定 per-flow decrypt allocation identity，并扩大
zeroize、capacity、reentrant、Pending/partial 状态面。length→payload read-ahead 后延迟 open 也被
否决，因为它让完整 ciphertext 额外跨一个 outer poll，反而扩大已知 locality 风险。

单遍 destructive AES-GCM（认证完成前可在 TLS 中暂存候选 plaintext，失败清 output）在密码学上可以
实现，但 hot/cold 结果已经否定其“两遍读取是瓶颈”的性能前提。为此引入自写 J0/counter/GHASH、
常量时 tag、硬件批处理和额外 key state 的审计成本不成比例，故 NO-GO：不实现、不建立产品提交、
不运行正式 workload。

阶段 3 因此停止于 `bf4cd4a6`：保留 copy-in 作为当前已验证的 locality pass，保留 fused sink 删除
copyback 的弱正向；不再制造 copy-in、direct receive、same-poll 或自研 crypto 候选。本阶段没有满足
触发第二次 hosted CI 的本地强正向结果，因此不创建 CI run。90% 总目标仍未完成；后续若继续，应由
用户明确授权进入阶段 4 或新的 profile 证据支持的独立架构轴。

## 13. 停止条件与后续

- 若 direct ratio `>=90%`：停止热路径改动，保留 scale trade-off，后续另立 connection-sharding任务。
- 若 `<90%`：本次候选与 CI 证据永久保留；不得从测量失败提交叠加产品优化。阶段 2/3 已停止；
  只有获得后续阶段授权或新的 profile 证据时，才从 `bf4cd4a6`、`d874d3dd` 或其它已证明节点开
  独立 sibling branch。
- 不实施 TUN 优化，不用不安全/不零化 ring 结果填补差距。

## 14. 90% 目标续跑：generic relay 调度诊断

代码与历史审计确认，`64cd1410` 同时引入 single-hop fused dispatch、完整 fused state
machine、Tokio adapter 和 wire final-layout，仓库中没有从后续已证明节点做过“只禁用 fused、恢复
Tokio 标准 copy loop”的精确 A/B。`relay_client_flow`/`relay_server_flow` 当前每个完整 frame 都
`wake_by_ref + Pending`；Tokio `copy_bidirectional_with_sizes` 则在同一次 poll 中继续搬运，直到真实
I/O `Pending` 或 cooperative budget 生效。这一差异能够直接放大已经证实的多 worker task migration，
且与 AEAD primitive 无关。

新建 diagnostic-only sibling：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-generic-relay-diagnostic`；
- 单变量：client/server 的普通 single-hop Shadowsocks TCP 强制经 `TokioFramed`、既有
  `relay_lifecycle` 和 Tokio bidirectional copy；
- 有意重新引入每端每连接两块 32 KiB generic relay buffer 及明文 copy，以换掉 fused 的逐帧
  scheduling boundary；idle、cancel、stats、half-close、backpressure 与 buffer owner accounting 保持；
- diagnostic commit 必须在 workload 前提交并推送；它无论结果如何都不作为产品祖先，也不触发
  hosted CI。

只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk` 正式本地样本，
不重跑、不挑样本。判定预先固定：相对 `bf4cd4a6` 的 `234,378,581 B/s`，不高于父节点即冻结；
正向但低于 `10%` 只记为不足；达到 `+10%` 且吞吐/proxy CPU 效率不下降，才认为 fused 调度语义
得到足够强的产品级根因支持。命中后仍从 `bf4cd4a6` 另开 sibling，在 protocol-owned buffer 内实现
同 poll 连续推进，保留 fused 的 buffer/copy 优势；不得从 generic diagnostic 叠加产品修改。

### 14.1 唯一正式样本与冻结决定

诊断提交已在 workload 前提交并推送：

- commit：`c84b5bc27816f28989adf0a70660e988a2c731da`；
- tree：`e08699e58d4fffc570cdeed030b486bcc27d019c`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-generic-relay-diagnostic`。

两路独立审查确认 TCP 方向统计、idle/cancel 优先级、half-close、backpressure、registry accounting
均保持，且没有 TUN、wire framing 或 crypto 变化。实验有效性审查同时限定了结论边界：该候选同时
改变 generic buffer/copy、fused direction/budget、progress atomic 提交频率，因而只能诊断整个
generic relay 与 fused engine 的净差，不能把差值全部归因于 self-wake。

固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk` 的唯一正式样本为：

- `250,408,686 B/s`，`3,756,130,304` checked bytes，`57,314` transactions；
- 相对 `bf4cd4a6` 的 `234,378,581 B/s` 为 `+6.8394%`；
- proxy CPU `23,860 ms`，相对 `23,180 ms` 为 `+2.9336%`；
- 吞吐/proxy CPU 效率由 `10,111.242` 增至 `10,494.916 B/s/ms`，为 `+3.7945%`；
- proxy migrations `83,568`，相对 `123,973` 为 `-32.5918%`；
- proxy context switches `484,355`，相对 `505,073` 为 `-4.1020%`；
- CPU busy `48.841%`，相对 `47.156%` 增加 `1.685` 个百分点；
- runner status `PASS`，`sample_count=1`，没有重跑。

吞吐和 CPU 效率方向为正，且 migrations 明显降低，说明减少 fused scheduling boundary 与改善
worker ownership 值得继续；但吞吐未达到预声明的 `+10%` 根因支持门槛。故该结果定性为“方向性
信号但证据不足”：提交与分支永久保留并冻结，不跑 hosted CI，不作为任何产品提交的祖先。下一候选
必须从 `bf4cd4a6` 新开 sibling，保留 fused buffer/copy 优势，只消融跨完整 frame 的人工 yield。

## 15. 产品 sibling：fresh download 的一次有界 continuation

历史复核进一步限定了最小未测 seam。`d874d3dd` 只在 outer poll 入口已经携带 Pending/partial
plaintext、且本次把它完整写入 sink 后，额外调用一次 `poll_download_once`；普通 fresh frame 完整
写入后仍立即 `wake_by_ref + Pending`。`fd5a42de`、`7e3f137a`、`0ad5cab5` 改的是 frame 内部的
length→payload/partial ready drain，均未修改这一 fresh-completion 分支。前者在 4 worker 下 `-6.15%`，
因此本轮不得把其 frame 内循环、64-I/O/256-KiB/8-frame budget 或任何 length→payload 合并带回来。

新建产品 sibling：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-bounded-frame-drain`；
- 生产改动只允许位于 `flow/fused.rs`：fresh download frame 完整写入后，与 carried completion 一样
  fall through 到既有的第二次 `poll_download_once`；
- 正常 `DataRx::Length { filled: 0 }` 下，第二次调用最多读取下一 frame 的 encrypted length，随后仍由
  `flow/io.rs` 的既有 `wake_by_ref + Pending` 公平边界停止；不得在同一 poll 进入其 payload；
- 每个 outer poll 仍最多调用两次 `poll_download_once`。第二次若真实 I/O Pending，依赖 transport/sink
  waker；若完成 plaintext 或方向结束，沿既有处理；upload、crypto、buffer ownership、idle、stats、
  cancel、half-close、initial payload、generic/multi-hop、TUN 均不变。

这会删除 fresh frame completion 与下一 frame length read 之间的一次纯 fused 调度往返，同时保留
历史证明对多 worker 公平性重要的 length→payload 边界。机制测试必须直接证明：同一个 outer poll
完成 frame 1 payload 与 sink write、读取 frame 2 length，但不读取 frame 2 payload；后续 poll 才发布
frame 2。还必须保持 carried Pending/partial 的一次 continuation 上界、认证失败不发布、zero frame、
EOF、partial sink、双向轮换和结构计数合同。

候选必须先通过 targeted/all-features Shadowsocks、client/server compile、Clippy、fmt、diff-check 与
独立审查，再提交并推送。之后只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream
`tcp-bulk` 正式本地样本，不重跑、不挑样本。判定预先固定：

- 不高于 `bf4cd4a6` 的 `234,378,581 B/s`：失败、保留并冻结，不跑 CI；
- 正向但低于 `+5%`：只记为弱正向、保留并冻结，不跑 CI；
- 达到 `+5%` 且吞吐/proxy CPU 效率不下降：本地强正向，提交与分支保留，并且只触发一次
  authoritative hosted direct CI；CI 不重跑。

若失败，先用该唯一候选二进制的 poll/wake/ready-state 计数与 CPU 调度证据区分“下一 length 大多
真实 Pending、因此 continuation 没有命中”与“命中但方向轮换/idle-progress 开销仍主导”；诊断不用于
性能排名。解决根因的新产品尝试仍从 `bf4cd4a6` 开 sibling，绝不从失败提交叠加。

### 15.1 唯一正式样本、失败判定与根因方向

候选在 workload 前提交并推送：

- commit：`d27f96ce4cacd87c9ba7c2508540249274392261`；
- tree：`561af4c1e4349a134d0b65d6fc2e5ce88b84c522`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-bounded-frame-drain`。

生产 diff 只有 `flow/fused.rs` 的 fresh-completion 控制流；另一文件为机制测试。两路独立审查为
PASS、无 blocker。Shadowsocks all-features 全套、no-default check、client/server all-features、
Clippy `-D warnings`、fmt、diff-check，以及真实进程三密码套件 bytes + half-close 矩阵均通过。

clean、pushed HEAD 的候选专属 profiling 二进制只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒
active、8-stream `tcp-bulk` 正式样本；合同为 `status=PASS`、`sample_count=1`、
`runner_exit_status=0`、47,491 transactions、`3,112,370,176` checked bytes，即
`207,491,345 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `5108b3e04e0297fdd280759c02f55a723e78da46f1dd682f2c53abc765895900` |
| `ferrum2-client` | `13100bcac679733060431b825103178efa1c1cf8984d53319b8d76d638cb06b2` |
| `ferrum2-server` | `87c546901f89eb20c97365c968ad2395e6df473d1c7c8fb795d13939c52b15d5` |

相对 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `26,887,236 B/s`（`-11.4717%`）；proxy CPU
从 `23,180 ms` 降至 `22,260 ms`（`-3.9689%`），吞吐/proxy CPU 效率从 `10,111.242` 降至
`9,321.264 B/s/ms`（`-7.8129%`）；migrations 从 `123,973` 增至 `130,897`
（`+5.5851%`），context switches 从 `505,073` 降至 `481,740`（`-4.6197%`），mean CPU busy
从 `47.156%` 降至 `44.517%`（`-2.639` 个百分点）。

按预声明门槛立即判失败：提交与分支永久保留并冻结，不重跑、不触发 hosted CI、不作为后续产品
祖先。吞吐、proxy CPU 和全机 busy 同时下降，排除“增加 ready work 导致 CPU 饱和”；migrations
反而增加，也不支持改善 cache ownership。当前最强、尚待 exact-binary 计数闭合的假设是：fresh
completion 后的 eager next-length poll 经常得到真实 transport `Pending`，候选随即只依赖 reactor
wake，删除了基线 frame-completion 的 synthetic local-queue retry，因而降低 runnable pipeline 填充。
该形态与 `7e3f137a` 删除 transition retry 后的大回归、以及 `0ad5cab5` 补 retry 后恢复大部分缺口一致。

下一步只对 `d27f96c` 的固定二进制或 diagnostic-only descendant 量化第二次 poll 的
Ready/Pending/EOF/error outcome；诊断吞吐不得用于排名。若 Pending 占主导，新产品 sibling 从
`bf4cd4a6` 开始：保留一次 next-length 尝试，但在该第二次调用返回 Pending 时补一次有界
`wake_by_ref`，让 ready 命中合并、真实 Pending 保留基线 retry。若证据不支持该分支，则回到
generic diagnostic 揭示的 lifecycle/progress/direction engine 成本，不叠加 `d27f96c`。

### 15.2 structural outcome 诊断

固定 `d27f96c` profiling ELF 的 uprobe 地址已由反汇编确认，但本机 tracefs 写权限被拒且没有免密
sudo，因此没有绕过权限安装 probe。改从失败候选建立永久 diagnostic-only descendant：

- 分支：`codex/tcp-hot-path-stage3-bounded-frame-pending-diagnostic`；
- commit：`27d98db41685191c9397be7df76014c9b2f3c435`；
- tree：`fec07f901110e2a6b66c8966a8e90e7fcf39c154`；
- parent：`d27f96ce4cacd87c9ba7c2508540249274392261`。

只在 `structural-metrics` build 中，第一次 fresh plaintext completion 后记录第二次
`poll_download_once` 的 receive state；计数先留在 per-flow 普通 `u64`，flow Drop 时才一次汇总。
默认产品 build 没有这些字段、分支或原子更新。该冻结诊断局部扩展 structural family 为 56；它不进入
现有 schema-v7 CI，也不调用仍固定 49 family 的 Python validator。

唯一一次非权威 structural workload 为 8 workers、1 秒 warm-up + 15 秒 active，正确校验
`5,143,265,280` bytes，`performance_authoritative=false`、`performance_adoption_allowed=false`。
计数完整闭合：

| 角色 | fresh attempts | next length ready 后 yield | next length 真实 Pending | ready 比例 | Pending 比例 |
| --- | ---: | ---: | ---: | ---: | ---: |
| client | 175,034 | 121,843 | 53,191 | 69.6110% | 30.3890% |
| server | 171,818 | 145,500 | 26,318 | 84.6826% | 15.3174% |
| 合计 | 346,852 | 267,343 | 79,509 | 77.0770% | 22.9230% |

partial/other Pending、第二次 ready plaintext、error、EOF 均为 0；attempts 精确等于 ready + real
Pending。结果否定“speculative next-length 几乎总是无效 poll”：77.08% 确实合并了下一 length；但
22.92% 的真实 Pending 会删除基线 frame-completion retry。仅 outcome 比例还不能区分“这四分之一
任务过早睡眠”与“77% ready batching/current-worker binding 本身破坏公平性”，下一产品 sibling 用
恢复比例闭合。

## 16. 产品 sibling：fresh next-length 的 one-shot Pending retry

从 `bf4cd4a6` 新开 `codex/tcp-hot-path-stage3-fresh-length-retry`，不得让 `d27f96c` 成为祖先。
相对基线只在原 guaranteed frame-completion wake 前尝试一次 next-length poll：

- 保留 `carried` 快照；carried completion 维持 `d874d3dd` 原行为；
- fresh completion 调用一次既有第二次 `poll_download_once`；
- 该第二次调用若返回 Pending，仅 fresh 路径补一次 `wake_by_ref`；
- 下一 outer poll 的普通 Length/Payload Pending 不再补 wake，因此静默连接不会 busy-loop；
- Ready length 仍保持 `flow/io.rs` 的 length→payload 公平边界；EOF/error/DirectionDone 不补 wake；
- 不改 `io.rs`、upload、crypto、buffer ownership、lifecycle、TUN 或编译参数。

测试必须证明：真实 next-length Pending 只产生一次 retry；立即消费 retry 后若仍 Pending 不再 wake；
外部 readiness 到来后只读 length、不读 payload；ready/partial length 无丢失或重发；carried completion
不获得新增 retry；EOF/error 无尾随 wake；既有 auth、zero、partial sink、双向公平与 half-close 保持。

候选先提交推送，再只跑一次既定 CPU `0-3`、3+15 秒、8-stream 正式样本。除相对 `bf4cd4a6` 的
产品门槛外，记录 recovery ratio：

`(candidate - 207,491,345) / (234,378,581 - 207,491,345)`。

- recovery `>=80%` 但仍不高于 `bf4cd4a6`：确认缺 retry 是 `d27f96c` 主因，但 prefetch 无产品收益，
  保留并冻结；
- recovery `<=30%`：ready batching/current-worker binding 是主因，停止整个 cross-frame prefetch seam；
- 高于 `bf4cd4a6` 但 `<+5%`：弱正向，保留并冻结，不进 CI；
- 相对 `bf4cd4a6 >=+5%` 且吞吐/proxy CPU 效率不下降：本地强正向，只触发一次 hosted direct CI。

无论结果如何都保留提交，不重跑；失败后的产品尝试仍从 `bf4cd4a6` 或其它已证明节点另开 sibling。

### 16.1 唯一正式样本、失败冻结与根因闭合

候选在 workload 前完成全部门禁、两路独立审查、提交与推送：

- commit：`c8537fce2b477d4bbbba2e17ff84f67c15ccabe5`；
- tree：`e41324691be55ae6d06a7d45797f22c44a5b8a51`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-fresh-length-retry`。

生产 diff 只在 `flow/fused.rs` 保留 fresh completion 后的一次 next-length poll，并在其真实 Pending 时
补回一次基线 self-wake；另一文件仅为机制测试。Shadowsocks all-features、no-default、Clippy
`-D warnings`、fmt、diff-check、client/server all-features compile、两端二进制 build，以及真实进程
三密码套件 bytes + half-close 矩阵均通过。正确性审查确认下一 outer poll 若仍 Pending 不再 self-wake，
不存在 busy-loop；实验审查确认 `d27f96c` 不在祖先链且测量配置未变。

clean、pushed HEAD 的候选专属 profiling 二进制只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒
active、8-stream `tcp-bulk` 正式样本；合同为 `status=PASS`、`sample_count=1`、
`runner_exit_status=0`、46,805 transactions、`3,067,412,480` checked bytes，即
`204,494,165 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `ffae388919a92c981f138015ee82b14a7a852755a539616719e8677de92440ff` |
| `ferrum2-client` | `22ea3dbb54a1ef4b158c29d975dcb625075c33506832a7b4f7011b4f10cc4178` |
| `ferrum2-server` | `b298c07c3455e12930e90b371747d7ec27c1b81173194ecf0e7b3a8c334a31e7` |

相对 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `29,884,416 B/s`（`-12.7505%`）；proxy CPU
从 `23,180 ms` 降至 `22,020 ms`（`-5.0043%`），吞吐/proxy CPU 效率从 `10,111.242` 降至
`9,286.747 B/s/ms`（`-8.1542%`）；migrations 从 `123,973` 增至 `131,241`
（`+5.8626%`），context switches 从 `505,073` 降至 `478,959`（`-5.1703%`），mean CPU busy
从 `47.156%` 降至 `43.882%`（`-3.274` 个百分点），migrations/byte 恶化 `21.3331%`。

相对无 retry 的 `d27f96c`，吞吐仍下降 `1.4445%`，CPU 下降 `1.0782%`，效率下降 `0.3703%`，
migrations 增加 `0.2628%`；恢复率为 `-11.1472%`。因此补回 synthetic retry 没有恢复任何缺口，
按预声明的 `recovery <=30%` 分支闭合：`d27f96c` 的主因不是 22.92% real Pending 删除了 retry，
而是 fresh completion 后跨 frame 的 eager next-length batching/current-worker binding 这条 seam 本身。
两个独立产品样本都同时表现为吞吐、CPU/busy 下降而 migrations/byte 上升，与额外 CPU 饱和不符，
也不能再把问题归因于 lost wake。

解决方式是停止整个 cross-frame prefetch seam：后续 sibling 完整保留 `bf4cd4a6` 的 fresh frame
completion `wake_by_ref + Pending`，不在同一 outer poll 触碰下一 frame length。`c8537fce` 永久保留并
冻结，不重跑、不触发 hosted CI、不作为产品祖先。下一产品尝试直接从 `bf4cd4a6` 新开，只在现有
frame/方向公平边界内部削减 generic 诊断所指向的 progress/activity 原子、direction engine 或 partial
I/O 成本；不得再以 read-ahead、bounded drain 或 retry 形式重开 cross-frame seam。

## 17. 产品 sibling：fused progress stats 的生命周期批量发布

generic relay 诊断仍在每次 destination write 后即时执行 `ActivitySignal::mark`，因此它没有减少 idle
activity 的 dirty/Notify 触发点；但方向 byte stats 留在 `ActivityIo` 的普通 `u64`，只在方向 Drop 时
调用一次 `AtomicU64::fetch_add`。`bf4cd4a6` 的 fused 路径则在每次完整或 partial destination write 后
直接调用 `RelayProgress::record`，同时执行 stats 原子和 activity 原子。下一 sibling 只隔离这一差异：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-batched-relay-progress`；
- runtime 提供 engine-owned RAII recorder：每次非零 write 用普通方向 `u64` 累加并立即 mark activity；
  recorder Drop 时每方向至多一次调用既有 `add_stats_only`；
- client single-proxy 与 server direct fused callsite 改用该 recorder，方向映射保持不变；
- engine 正常、I/O error、idle 或 cancellation 被 drop 时，recorder 必须先发布，再由 lifecycle 读取最终
  `RelayStats`；zero bytes 不计 progress；
- 不改 `fused.rs`、`flow/io.rs`、wire、crypto、frame/poll/wake、buffer ownership、generic fallback、
  TUN、runtime worker 或测量配置。

这会把 fused stats 更新从每次成功 frame/partial write 一个 `AtomicU64` 降为每连接生命周期每方向至多
一次，同时完整保留每次真实写入后的 idle deadline reset。机制测试必须覆盖 Drop 前 stats 未发布、
Drop 后双向 totals 精确、zero 不标记 activity，以及 I/O/cancel/idle 三种 engine drop 路径的 partial
stats；既有 cancellation 优先级、敏感错误不泄漏、bytes、partial I/O 与 half-close 合同保持。

候选先通过 runtime/shadowsocks targeted 与全套、client/server all-features compile、Clippy、fmt、
diff-check、独立 correctness/experiment 审查和三密码套件真实进程 bytes + half-close，再提交并推送。
之后只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk` 正式本地样本：

- 不高于 `bf4cd4a6` 的 `234,378,581 B/s`：失败、保留冻结、不进 CI；
- 正向但低于 `+5%`：弱正向、保留冻结、不进 CI；
- 达到 `+5%` 且吞吐/proxy CPU 效率不低于 `10,111.242 B/s/ms`：本地强正向，只触发一次 hosted
  direct CI；CI 不重跑。

无论结果如何都先保留提交和远端分支，不重跑。失败时不得在该提交上叠加 activity、sink drain 或
upload batch；下一产品轴仍从 `bf4cd4a6` 新开 sibling。

### 17.1 唯一正式样本与失败冻结

候选在 workload 前通过 runtime 全套、Shadowsocks all-features、client/server all-features compile、
受影响三包 Clippy `-D warnings`、fmt、diff-check、两路独立审查，以及真实进程三密码套件 bytes +
half-close；随后提交并推送：

- commit：`54147afb6969c0105a121eda29ef1a8df62a3476`；
- tree：`00fe732f88bf3d9e03e786a7df43f7621b5d905e`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-batched-relay-progress`。

唯一正式样本固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk`，合同为
`status=PASS`、`sample_count=1`、`runner_exit_status=0`、52,521 transactions、
`3,442,016,256` checked bytes，即 `229,467,750 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `205672b4b35042191e177cf05d55c80f5d6a985bb6255bef21e35969fde32b26` |
| `ferrum2-client` | `a34ebedc3ef53f23843d25975f0f5040c76792533caedbfb3cf82e347321b797` |
| `ferrum2-server` | `08e482ac67ddac5acc354541f1ccf7cbabc7a456b8cb2ef387ec2fd812b8bdf3` |

相对 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `4,910,831 B/s`（`-2.0953%`）；proxy CPU
从 `23,180 ms` 增至 `23,230 ms`（`+0.2157%`），吞吐/proxy CPU 效率从 `10,111.242` 降至
`9,878.078 B/s/ms`（`-2.3060%`）；migrations 从 `123,973` 增至 `132,862`
（`+7.1701%`），context switches 从 `505,073` 增至 `513,327`（`+1.6342%`），mean CPU busy
从 `47.156%` 增至 `47.461%`（`+0.305` 个百分点），migrations/byte 恶化 `9.4637%`。

候选未达到父节点，按预声明立即失败：提交与远端分支永久保留并冻结，不重跑、不触发 hosted CI、
不作为后续产品祖先。结果排除每次 destination admission 的方向 `AtomicU64::fetch_add` 是 generic relay
净 `+6.8394%` 的主要来源；减少该原子既没有降低 CPU，也没有改善 migrations。下一步先用
diagnostic-only structural counters 量化 `FtbrPartialWrites / FtbrBorrowedDownloadFrames`：只有 download
partial sink write 命中面明显时，才从 `bf4cd4a6` 开 same-frame ready sink drain sibling；否则直接转向
不改 frame I/O 的 activity/scheduler lifecycle seam。不得在 `54147afb` 上叠加任何优化。

## 18. partial-write 命中面诊断与 poll-local activity sibling

### 18.1 bf4 structural diagnostic：same-frame sink drain NO-GO

不修改产品代码，直接用 `bf4cd4a6` 的既有 schema-v7 `structural-metrics` 构建运行一次
diagnostic-only workload：1 秒 warm-up + 15 秒 active、8 workers，正确校验 `6,639,845,376`
bytes；`status=PASS`、`performance_authoritative=false`、
`performance_adoption_allowed=false`，结果不参与性能排名。固定身份为：

- candidate：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- tree：`4fcf9a25c47e251eb42aa24f8a6eb62fa1d702c0`；
- `m4-qualification`：`94d6a920a74b067e1f7bf9b0028ec4fb6d55c8a331e78536b453027c5a0491f9`；
- `ferrum2-client`：`194f2b0575411c9bdc1e3e0af5d4f35ed26c489e8dd54a444984bbab18394db3`；
- `ferrum2-server`：`b890b71b3b6e3e31aad2b63fdcdc7445abda1955c4adc63a24978099fbe29d50`。

计数结果：

| 角色 | borrowed download frames | owned upload frames | fused partial writes |
| --- | ---: | ---: | ---: |
| client | 217,188 | 217,133 | 0 |
| server | 217,133 | 217,188 | 0 |
| 合计 | 434,321 | 434,321 | 0 |

`FtbrPartialWrites / FtbrBorrowedDownloadFrames = 0 / 434,321`。因此“仅在同一已认证 frame 内继续
Ready partial sink writes”在目标 workload 没有命中面，直接 NO-GO：不实现、不建产品提交、不跑
正式性能。上传 `drain_staged` 已经在同 poll 循环 Ready partial tunnel writes；ready upload batch 只能
跨 frame 读取下一 plaintext，也按已关闭的 read-ahead/bounded-drain seam NO-GO。

### 18.2 产品 sibling：poll-local activity deadline reset

现有 `ActivitySignal::mark` 对每次 destination progress 执行 `AtomicBool::swap(true, Release)`，dirty
首次翻转时还执行 `Notify::notify_one`；idle future 再在 `timer/notified` select 中消费 dirty。specialized
engine、idle 与 cancellation 实际由同一个外层 biased select 在同一 task 中轮流 poll，顺序固定为
cancellation、engine、idle：engine 在本轮产生 progress 并返回 Pending 后，idle 必定在同一外层 poll
中被继续 poll。故可以让 idle 每次被 poll 时先消费 dirty/reset timer，再 poll timer，不需要额外 Notify
唤醒同一个 task，也不需要 mark 侧的 read-modify-write。

新建 sibling：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-poll-local-activity`；
- 生产 diff 只允许位于 `crates/ferrum2-runtime/src/relay.rs`：`mark` 用 atomic store 设置 dirty，删除
  `Notify`；idle 改为 `poll_fn`，每次 poll 先 `take_dirty` 并将 `Sleep` reset 到 `now + timeout`，再 poll
  timer；
- 外层 cancellation > engine > idle 优先级、direction stats 的每次 `AtomicU64` 更新、frame/poll/wake、
  I/O、half-close、buffer、crypto、generic copy、TUN 与测量配置全部保持 `bf4`；
- common generic lifecycle 也使用同一 activity 机制，必须保持其可观察 idle/bytes/error 合同；正式 direct
  workload 仍只覆盖 client/server fused 产品路径。

机制测试必须证明：首次/重复 progress 都只延后一个 fresh deadline；t=4 秒的 progress 将 5 秒 timeout
推迟至 t=9；timer 与 progress 同轮 Ready 时 progress reset 胜出；zero 不重置；engine I/O、cancel、
正常完成与 idle 的既有优先级和精确 stats 保持；真实 generic 与 fused half-close/backpressure 不变。

候选通过 runtime 全套、client/server compile、相关 Clippy、fmt、diff-check、两路独立审查和三密码套件
真实进程 bytes + half-close 后，必须先提交推送，再只运行一次固定 CPU `0-3`、3 秒 warm-up + 15 秒
active、8-stream `tcp-bulk` 正式样本：

- 不高于 `bf4cd4a6` 的 `234,378,581 B/s`：失败、保留冻结、不进 CI；
- 正向但低于 `+5%`：弱正向、保留冻结、不进 CI；
- 达到 `+5%` 且吞吐/proxy CPU 效率不低于 `10,111.242 B/s/ms`：本地强正向，只触发一次 hosted
  direct CI；CI 不重跑。

无论结果如何都保留提交与远端分支，不重跑；若失败，下一产品尝试仍从 `bf4cd4a6` 开 sibling，不在
本提交上叠加。

### 18.3 唯一正式样本与失败冻结

候选在 workload 前通过 runtime 全套、client/server all-features compile、相关 Clippy
`-D warnings`、fmt、diff-check、三密码套件真实进程 bytes + half-close，以及修复一次 off-engine
`RelayProgress::record` 契约 blocker 后的两路独立复审；随后提交并推送：

- commit：`c02502486ad7fd65a634355c8b291ea01bd131fd`；
- tree：`c5aae411201aeb7cc1a898e82b249e3f14d98a79`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-poll-local-activity`。

唯一正式样本固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk`，合同为
`status=PASS`、`sample_count=1`、`runner_exit_status=0`、51,442 transactions、
`3,371,302,912` checked bytes，即 `224,753,527 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `87e961b21913d2b783dd6d46cde1777d19ef04ed7c65058cffc808c65c77f0c3` |
| `ferrum2-client` | `19dfc3020e3eed5bcb353bc1d245c4f1bebb2b4f7c95a42d1591117828c79a8d` |
| `ferrum2-server` | `30c0bfa12d3437fc77a418574b53a0b343af30397c6bc39da9f6d76eec2f6dc3` |

相对 `bf4cd4a6` 的 `234,378,581 B/s` 下降 `9,625,054 B/s`（`-4.1066%`）；proxy CPU
从 `23,180 ms` 降至 `22,590 ms`（`-2.5453%`），吞吐/proxy CPU 效率从 `10,111.242` 降至
`9,949.249 B/s/ms`（`-1.6021%`）；migrations 从 `123,973` 降至 `123,751`
（`-0.1791%`），context switches 从 `505,073` 降至 `495,557`（`-1.8841%`），mean CPU busy
从 `47.156%` 降至 `46.211%`（`-0.945` 个百分点），但 migrations/byte 仍恶化 `4.0958%`。

候选未达到父节点，按预声明立即失败：提交与远端分支永久保留并冻结，不重跑、不触发 hosted CI、
不作为后续产品祖先。删除 activity RMW/Notify 虽小幅降低 CPU、context switches 与绝对 migrations，
吞吐却下降更多；因此这组原子/通知不是 generic relay 净 `+6.8394%` 的来源，baseline 的 notification
也可能帮助维持 runnable pipeline。结合 17.1 与 18.1，per-write stats、activity 和 partial sink seam
均停止。下一产品设计必须直接处理 generic 与 fused 的 engine/buffer 结构差异，并继续从
`bf4cd4a6` 开 sibling；不得把上述失败消融重新组合。

## 19. 产品 sibling：client/server 固定 request-first poll order

Tokio 1.53.1 `copy_bidirectional_impl` 每个 poll 固定先 `a→b`、再 `b→a`。generic diagnostic 的
callsite 顺序使 client 固定先 SOCKS/plain→tunnel，server 固定先 tunnel→target，即两端都先推进请求
因果链。`bf4cd4a6` 的 `FusedRelay` 则每个 outer poll 翻转 `upload_first`：client 在请求/响应优先之间
交替，server 还从响应优先开始交替。历史 `git log --all -S upload_first` 只找到 `64cd1410` 引入，
没有从 `bf4` 独立测过 fixed role-aware request-first。

该 seam 不减少 helper 调用数或显式 wake：首方向 Pending 时仍继续 poll 第二方向；它只改变同一 outer
poll 内的 readiness、cooperative budget 与同时错误优先级。架构审查认为预期收益较弱，但这是进入完整
protocol-owned copy engine 前最后一个无需新增 buffer/state machine、可以精确排除的 generic 差异，
故以严格门槛运行一次产品 A/B：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-request-first-order`；
- private fused constructor 接收固定 first direction；client 传 `PlainToTunnel`，server 传
  `TunnelToPlain`；删除 per-poll toggle，但每 poll 仍各调用 upload/download 一次；
- 不改方向 helper、任何 `wake_by_ref`、frame/length/payload、I/O、buffer、crypto、progress/lifecycle、
  worker、generic fallback、TUN 或测量配置。

机制测试必须连续多 poll 证明：client 始终 plain/request first，server 始终 tunnel/request first；首方向
Pending 后第二方向仍被 poll；双向 Ready 各推进一次；simultaneous error 的固定优先级明确；既有
partial、backpressure、bytes 与 half-close 保持。

候选通过 Shadowsocks targeted/full、client/server compile、相关 Clippy、fmt、diff-check、两路独立
审查和三密码套件真实进程 bytes + half-close 后，必须先提交推送，再只运行一次固定 CPU `0-3`、
3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk` 正式样本：

- 不高于 `bf4cd4a6` 的 `234,378,581 B/s`：失败、保留冻结、不进 CI；
- 正向但低于 `+5%`：弱正向、保留冻结、不进 CI；
- 达到 `+5%` 且吞吐/proxy CPU 效率不低于 `10,111.242 B/s/ms`：本地强正向，只触发一次 hosted
  direct CI；CI 不重跑。

若失败，固定顺序彻底停止；下一步先从 `bf4` 建 diagnostic-only counters，按 frame 区分 upload
ciphertext drain Pending 与 download sink Pending。只有 upload Pending 命中明显时，才设计
pending-only one-frame-ahead plaintext buffer；不得直接重建历史已删除的通用 `AsyncBufRead` relay。

### 19.1 唯一正式样本与弱正向冻结

候选在 workload 前通过 Shadowsocks targeted/full、client/server all-features compile、相关 Clippy
`-D warnings`、fmt、diff-check、两路独立审查，以及真实进程三密码套件 bytes + half-close；随后提交并
推送：

- commit：`c511314385143890cea0e80b422dff364817287a`；
- tree：`8e472d39a70da63a90289ba08b81f03acfbde19a`；
- parent：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-request-first-order`。

唯一正式样本固定 CPU `0-3`、3 秒 warm-up + 15 秒 active、8-stream `tcp-bulk`，合同为
`status=PASS`、`sample_count=1`、`runner_exit_status=0`、54,578 transactions、
`3,576,823,808` checked bytes，即 `238,454,920 B/s`。二进制 SHA-256 为：

| 二进制 | SHA-256 |
| --- | --- |
| `m4-qualification` | `b7102053c54b3d7805922d6994692c9c0bacd7990a0f5c5066f9c8c8a2120e68` |
| `ferrum2-client` | `814782ebb45330f6916627cf015801fb250d0d1e30bea1254fffbbec535489b6` |
| `ferrum2-server` | `7de33d7d0f3fa46c16381154277536453be67b7c567054c393acee4ed1667484` |

相对 `bf4cd4a6` 的 `234,378,581 B/s` 增加 `4,076,339 B/s`（`+1.7392%`）；proxy CPU
从 `23,180 ms` 增至 `23,450 ms`（`+1.1648%`），吞吐/proxy CPU 效率从 `10,111.242` 增至
`10,168.653 B/s/ms`（`+0.5678%`）；migrations 从 `123,973` 增至 `126,641`
（`+2.1521%`），context switches 从 `505,073` 增至 `515,159`（`+1.9969%`），mean CPU busy
从 `47.156%` 增至 `48.002%`（`+0.846` 个百分点），migrations/byte 恶化 `0.4058%`。

吞吐虽为正向，但远低于预声明的 `+5%` 门槛 `246,097,511 B/s`，因此判定为弱正向：提交与远端
分支永久保留并冻结，不重跑、不触发 hosted CI、不作为后续产品祖先。结果只支持固定 request-first
顺序可能贡献小幅 readiness/codegen 收益，不能单独区分固定方向、删除 toggle 或代码布局的贡献；
它同时排除了该顺序是 generic relay 净 `+6.8394%` 的主要来源。绝对 CPU、migrations 与 context
switches 均上升，跨核迁移强度没有改善，所以后续不再调整方向优先级。

下一步严格按 19 节预声明，从 `bf4cd4a6` 新开 diagnostic-only sibling，只增加按 frame 去重的
upload staged-ciphertext drain Pending 与 download authenticated-plaintext sink Pending 计数，并继续标记
`performance_authoritative=false`、`performance_adoption_allowed=false`。诊断只决定 pending-only upload
buffer 是否有真实命中面，不参与性能排名，也不消费产品候选的唯一正式样本。

## 20. diagnostic-only sibling：按 frame 量化真实 sink Pending

旧 schema-v7 structural diagnostic 使用 `tcp-stream-64k`：每 worker 连续写四个 64 KiB payload 后才读
回 echo；正式产品样本的 `tcp-bulk` 则每次写一个 64 KiB 后立即读回。前者会人为放大 socket
backpressure，不能用来决定正式 workload 是否值得增加 pending-only buffer。因此新诊断固定为：

- 基线：`bf4cd4a679b4d140615d0b61c89a0dd916b20e2a`；
- 分支：`codex/tcp-hot-path-stage3-pending-surface-diagnostic`；
- 新增 diagnostic-only feature `tcp-pending-surface-diagnostic`；普通产品、现有 UDP 性能流程及原
  `structural-metrics` 构建仍保持 schema-v7、49 counters 与 `tcp-stream-64k`，不改变 calibration；
- 只有该 feature 的 client/server/runner 构建启用 schema-v8、53 counters，并让 structural diagnostic
  使用与正式候选相同的 8-worker `tcp-bulk`：每次 64 KiB write 后立即 read exact；
- 现有 `validate-structural-diagnostic` 继续只接受 v7/49/`tcp-stream-64k`；新建
  `validate-tcp-pending-surface-diagnostic` 并只接受 v8/53/`tcp-bulk`。禁止根据 evidence 自选版本，
  以确保漏开 feature 而产生的 v7 evidence 必然被新诊断拒绝；
- 新增四个 feature-only counter：
  `tcp_fused_upload_drain_pending_frames`、`tcp_fused_upload_drain_pending_polls`、
  `tcp_fused_download_sink_pending_frames`、`tcp_fused_download_sink_pending_polls`；
- 所有热路径计数先累加到既有 per-relay 普通 `u64/bool`，relay Drop 时才一次发布到 structural shard，
  不把逐 poll 原子引入产品测量。

上传只统计 relay 已成功 seal 的 data frame：构造时 `pending_upload_plaintext=Some(0)` 所代表的握手/首响应
staged wire 必须排除。每个 data frame 在 `poll_drain_upload` 每次返回 `Pending` 时增加 polls，首次
Pending 才增加 frames；wire 完整 drain 后关闭并清除 per-frame seen。下载同时覆盖 decrypt-to-real-sink
直接交付的 `FusedSinkPoll::Pending`，以及剩余 authenticated plaintext 对 real sink 的后续
`poll_write::Pending`；两条路径共享 per-frame seen，direct Pending 转为 buffered remainder 后仍只算
一个 frame。schema/runner/controller 必须拒绝以下不变量：`frames > polls`、upload pending frames 大于
owned upload frames、download pending frames 大于 borrowed download frames。

诊断候选完成机制测试、schema-v7 未启用时的回归测试、schema-v8 fail-closed consumer 测试、M4
self-check、client/server feature compile、Clippy、fmt、diff-check 与两路独立审查后，先提交并推送，
再只运行一次 diagnostic workload：CPU 不作为产品排名输入，1 秒 warm-up + 15 秒 active、8 workers，
`performance_authoritative=false`、`performance_adoption_allowed=false`。不得把它当正式产品样本，也不
触发 CI。

对 client、server 与 merged 分别计算：

- `U = upload_pending_frames / owned_upload_frames`；
- `D = download_pending_frames / borrowed_download_frames`；
- `S = upload_pending_polls / max(upload_pending_frames, 1)`。

pending-only upload buffer 的决策在运行前固定为以下有序规则，命中第一条后立即停止：

- 若既有 `tcp_fused_partial_writes` 非零：强制 NO-GO；此时 upload drain 的 caller-level `Pending`
  可能混入 fairness budget exhaustion，不能诚实归因为 tunnel writer backpressure；
- 否则，`U_merged >= 10%` 且 client/server 各自 `U >= 5%`：GO；
- 否则，`5% <= U_merged < 10%`、两端各自至少命中一帧且 `S_merged >= 1.5`：条件 GO；条件
  GO 与 GO 的后续动作完全相同，必须自动进入产品 sibling，不允许再次人工筛选；
- 其余全部 NO-GO，包括 `U_merged < 5%`、任一端完全无命中、`U_merged >= 10%` 但任一端
  `U < 5%`，或中间区间未达到 `S_merged >= 1.5`。

`D` 只用于解释 generic buffer 的信号来源，无论多高都不得重开 download next-length/read-ahead seam。
若 upload 为 GO 或条件 GO，产品实现必须从 `bf4cd4a6` 另开 sibling，仅在当前 ciphertext drain 已真实
Pending 时预取最多一个 plaintext frame；不得从诊断提交继承。若 upload 为 NO-GO，pending-only
buffer 轴关闭，转向保持现有零拷贝 buffer ownership 的完整 protocol-owned cooperative pump 设计。
