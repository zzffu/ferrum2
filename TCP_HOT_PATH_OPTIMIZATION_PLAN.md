# Ferrum2 非 TUN TCP 热路径优化计划与证据账本

状态：阶段 2、阶段 3 已完成实现与本地分轴测量；single-worker 产品候选
`d64b068a7f090a26313f8113590cf39be85f12b8` 在唯一一次真实 hosted direct CI 中达到
`62.9574%`，未达 90%，失败分支和证据永久保留。后续尝试从其前方的 `d874d3dd` 开 sibling，
不把失败候选作为祖先。

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
公共基线另开 sibling branch。关键成功链为：

```text
7edf4fcc  当前非 TUN 产品公共基线
└── 20c3883b  partial handshake I/O
    └── 790a0aa9  worker-local TCP copyback port
        └── d874d3dd  download carried continuation
            └── 90dc643d  single-worker runtime diagnostic
                └── d64b068a  single-worker production runtime
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

新 sibling `codex/tcp-hot-path-stage3-two-worker-runtime` 再从 `d874d3dd` 开始：先独立测量每进程
2 个 Tokio worker，寻找“一核 locality”与“默认多核迁移”之间的最小可用迁移域。若仍失败，保留
提交并从 `d874d3dd` 再开 sibling，实施按连接稳定分片的多个 current-thread runtime；中央 accept
只分发连接，完整 flow 生命周期固定在 shard 内。

## 13. 停止条件与后续

- 若 direct ratio `>=90%`：停止热路径改动，保留 scale trade-off，后续另立 connection-sharding任务。
- 若 `<90%`：本次候选与 CI 证据永久保留；不得从测量失败提交叠加产品优化。下一尝试从
  `d874d3dd` 或后续已证明改善的成功节点开 sibling branch。
- 不实施 TUN 优化，不用不安全/不零化 ring 结果填补差距。
