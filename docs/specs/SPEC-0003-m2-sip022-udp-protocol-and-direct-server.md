# SPEC-0003: M2 SIP022 UDP protocol API 与 direct server

- **Status:** Approved
- **Milestone:** M2
- **Related ADRs:** `ADR-0020`、`ADR-0021`、`ADR-0022`；继续适用
  `ADR-0001`～`ADR-0007`、`ADR-0009`、`ADR-0016`～`ADR-0019`
- **Test plan:** `docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md`
- **Tickets:** M2-T01、M2-T02、M2-T03、M2-T04、M2-T05

## Objective and non-goals

交付以下可独立使用和验收的纵切：

```text
bounded ferrum2 SIP022 UDP client protocol API
  → AES-128 | AES-256 | XChaCha20-Poly1305 UDP packet
  → ferrum2-server UDP listener on server.listen
  → authenticated session-ID routing + bounded direct UDP socket
  → IPv4 | IPv6 | ASCII-domain target
  → bound response to latest validated client peer
```

并在一个 exact integrated SHA 上，以 pinned sing-box 和 shadowsocks-rust完成
`3 methods × 2 references × 2 directions = 12` 个 UDP cases。

非目标：

- SOCKS5 `UDP ASSOCIATE`、TUN、transparent proxy或任何public client UDP
  inbound/listener；
- client binary UDP schema/composition；
- routing、DNS proxy/cache/custom resolver、multiple upstreams、load balancing、
  chaining、management API、hot reload；
- SIP023、多用户、多PSK product behavior、method negotiation/fallback；
- ChaCha12/ChaCha8 或其他reduced-round methods；
- M3 native packaging/full lifecycle/soak 和 M4 benchmark/performance claim；
- push、hosted run/rerun、PR、tag、release或publish；这些另需明确授权。

## Public protocol behavior

### Method and crypto capability

- 只接受三个既有canonical methods；PSK仍为AES-128恰16 bytes、
  AES-256/ChaCha恰32 bytes。
- canonical profile为transport-neutral `MethodProfile`；
  `TcpMethodProfile` 在M2保持source-compatible alias。
- client/server protocol owner只取得method-bound opaque UDP crypto capability；
  raw PSK/subkey/expanded state不离开crypto。
- AES UDP严格使用ADR-0020的16-byte separate header、session-derived subkey和
  AES-GCM body；ChaCha UDP严格使用direct PSK、fresh 24-byte nonce和
  XChaCha20-Poly1305。
- method在session创建前固定；peer不能协商、降级、探测或触发另一method重试。

### Packet API

Client API必须能够：

1. 通过validated limits manager创建bounded client session；
2. 把normalized IPv4/IPv6/ASCII-domain target和owned payload编码到
   caller-owned bounded buffer；
3. 完整认证/校验response的type、±30s timestamp、client-session binding、
   padding/address/length和association/replay后返回owned datagram；
4. 以closed/redacted error报告local bounds/random/key/counter failures；
5. 对peer packets静默drop authentication/semantic/replay/binding failures。

Server protocol API必须能够：

1. 消费hard-bounded wire buffer并完成method-specific authentication；
2. 完整校验type、timestamp、binding、padding、address和length后才暴露
   target/payload；
3. 在runtime capacity reservation后通过serialized owner原子commit
   replay/peer/activity；
4. 返回generation-bound response capability，不能暴露可自由构造的session key。

API不创建listener、不拥有Tokio process-global state、不执行routing policy。
Exact type/helper names除`MethodProfile` compatibility contract外是implementation
freedom。

### Wire bounds and semantics

- complete Shadowsocks UDP wire datagram hard maximum为65,507 bytes；
- encoder必须以checked subtraction从method、direction、address和padding
  overhead推导payload上限；不能truncate或overflow；
- valid target是nonzero-port IPv4、IPv6或1～255-byte ASCII domain；
- malformed/truncated/unknown ATYP、empty/oversized/non-ASCII domain、zero port、
  impossible padding/length、wrong type、stale timestamp或trailing ambiguity
  fail closed；
- packet type为client `0`、server `1`；timestamp差超过30秒按replay拒绝；
- response embedded client session ID必须匹配requesting client session；
- invalid input不能引发peer-sized allocation、resolution、socket、send、queue、
  accepted session/replay/peer/activity mutation或response。

## Session and replay behavior

### IDs and counters

- session IDs是8-byte CSPRNG values；client/server direction不同。
- fresh live ID最多尝试8次collision draw，仍冲突则终止affected session。
- outbound packet ID每direction从0开始，只有完整packet成为externally ownable
  后推进；所有u64 values最多使用一次，耗尽后fail closed，绝不wrap。
- ChaCha random nonce和AES key/nonce derivation都不得产生AEAD key/nonce pair
  reuse。

### Sliding replay window

- 每session、每incoming direction有独立window；
- represent highest及向后8,128个IDs，共8,129 values；
- duplicate和`highest - id > 8,128`拒绝；forward jump和arithmetic overflow安全；
- early precheck可用，但auth、全部semantic validation和capacity reservation后
  必须在serialized transition中recheck/commit；
- concurrent same-ID packets恰有一个可accepted。

### Routing, roaming and associations

- server只按authenticated client session ID路由；一个client session恰对应一个
  direct outbound UDP socket；
- valid accepted client packet才更新last-seen client source；response发送到该
  latest validated peer；
- same session ID改变source是合法roaming；same source不同session ID是不同
  sessions；
- client恰保留current + old两个server-session associations，各有独立replay
  window；
- first ID成为current；第二ID使原current降为old；只有old自最后valid packet
  起满60秒才可被第三ID替换，否则第三ID拒绝；
- invalid/duplicate packets不刷新association、idle或peer activity；
- session/association/replay state至少保留60秒，使用monotonic time；
- response handle带generation；remove/recreate后的stale target response拒绝。

## Runtime and resource behavior

Core只新增等价于normalized target + owned bytes的bounded datagram value，不改变
既有stream traits。Runtime是protocol-neutral owner，不依赖Shadowsocks。

| Resource | Contract |
|---|---|
| sessions | client API与server各默认4,096，validated range 1..=65,535 |
| user-space buffered bytes | global默认16 MiB，range 1 MiB..=256 MiB，按allocated capacity |
| queues | 每server session每direction固定4 datagrams |
| wire datagram | complete packet最大65,507 bytes |
| idle | 默认300s，range 60..=86,400s |
| domain resolution | system resolver，最多16 ordered candidates |

- scratch、encoded/decoded owned buffer和queue capacity都计入global permits；
  move不重复、shared backing不漏计，失败释放reservation。
- admission full先purge deterministic oldest eligible expired session；无expired
  则拒绝new session，绝不驱逐active/未到idle state。
- reservation成功后才可atomic replay commit；queue/byte/session race失败不得
  poison accepted state。
- domain resolution和candidate sends共用`runtime.connect_timeout_ms`形成的一个
  monotonic absolute per-datagram deadline；不能逐stage/candidate重置。
- cancellation、idle、target failure、listener failure和shutdown必须reap
  session/socket/task/buffer/queue owner；late response不能resurrect session。

## Server configuration and startup

Schema v1 additively接受：

```toml
[udp]
enabled = true
max_sessions = 4096
max_buffered_bytes = 16777216
idle_timeout_ms = 300000
```

- section/fields omitted使用defaults；range违反、unknown field或overflow以
  `config.semantic`/closed field在resource创建前失败；
- `enabled=false` 不创建UDP socket、session table、UDP worker或UDP activity；
- client binary schema不增加UDP section；
- `--check-config` success/failure/exit 0/1/2和redaction继续遵守ADR-0003，且不
  bind TCP/UDP/metrics或spawn task；
- enabled时TCP和UDP在同一个`server.listen` address/port bind；两个bind都成功
  后才启动loops，任一失败释放另一端和未启动owners；
- UDP listener terminal failure是process-fatal，统一cancel/reap TCP和UDP；
- graceful shutdown同时停止accept/receive，drain到既有
  `runtime.shutdown_grace_ms`，随后forced cancellation。

Existing config omitted `[udp]`时会默认开启UDP；如果UDP port已占用，M1成功的
TCP-only deployment升级后可能startup失败。Operator可显式设置
`[udp].enabled=false`保持M1 run behavior。

## Direct outbound, errors and observability

- IP target直接send；domain遵守ADR-0019的ASCII/16-candidate/system resolver
  boundary；
- malformed/unauthenticated packets静默drop，避免形成oracle；local API/config/
  runtime error只暴露closed category：
  `bounds/authentication/type/timestamp/address/padding/binding/duplicate/too_old/
  session_limit/buffer_limit/queue_full/clock/random/key/counter/resolve/send/
  receive/idle/cancelled`；
- affected datagram/session failure不终止unrelated sessions；UDP listener failure
  除外；
- stable UDP metrics是ADR-0022列出的七个families，labels只来自closed
  `role/direction/outcome/stage/reason`；
- PSK/key/nonce/session ID/packet ID/target/source/peer不得出现在log、error、
  panic、trace field或metric label；correlation使用process-local bounded ID；
- existing TCP metric names、labels和M0/M1 tracing behavior不变。

## Local and external acceptance behavior

Local product evidence：

- protocol API → composed ferrum2-server → direct UDP echo对三个methods各一条
  IPv4 row；
- focused IPv6/domain rows覆盖address/resolver adapter，不做method×address全
  cross product；
- 每row至少三条distinct request/reply datagrams；
- one stalled/saturated row证明real socket adapter传播backpressure；
- bind rollback、UDP disabled、expiry、shutdown/rebind和TCP regression通过。

Hosted case mapping固定：

| IDs | Method | case_id→direction/reference mapping |
|---|---|---|
| `M2-UDP-INT-001..004` | AES-128 | `001` ferrum→sing；`002` ferrum→ss-rust；`003` sing→ferrum；`004` ss-rust→ferrum |
| `M2-UDP-INT-005..008` | AES-256 | `005` ferrum→sing；`006` ferrum→ss-rust；`007` sing→ferrum；`008` ss-rust→ferrum |
| `M2-UDP-INT-009..012` | ChaCha | `009` ferrum→sing；`010` ferrum→ss-rust；`011` sing→ferrum；`012` ss-rust→ferrum |

这12案冻结唯一的case_id→transport/method/reference/direction mapping；providers
ready时每案恰执行一次。各案彼此独立，表格呈现、执行及summary行顺序均不是合同，
runner的确定性顺序只是实现细节。这不改变单flow内协议规定的framing、nonce、
handshake、payload与lifecycle顺序。

Ferrum-client方向launch `ferrum2-shadowsocks` Cargo example作为black-box
protocol-API adapter；`ferrum2-m0-harness`不得新增ferrum library dependency。
Reference-client方向使用reference提供的UDP ingress连接composed ferrum2-server，
不新增ferrum public client inbound。

每case独立temp/ports/children/absolute deadline/bounded redacted capture/cleanup，
并在一个session内验证三条distinct echo payload及observed source address。
Reference setup failure使其六rows在一个canonical root下FAIL，另一reference继续；
panic/timeout/missing/skipped/payload/source/cleanup/nonzero都不能PASS。只有同一
exact SHA/run/attempt的case_id-keyed 12-row set、12/12 + cleanup summary exit 0。

## Acceptance criteria

1. **M2-AC-01:** 三方法opaque crypto和committed fixtures证明AES separate-header/
   session AEAD、ChaCha XChaCha、exact keys、tamper和TCP profile compatibility。
2. **M2-AC-02:** Bounded packet API对IPv4/IPv6/domain request/response通过wire、
   timestamp/type/binding/padding/length/65,507 bounds及negative tests。
3. **M2-AC-03:** IDs/counters、8,129-value per-direction replay、current+old
   association、roaming、generation和post-validation atomic mutation通过。
4. **M2-AC-04:** Core/runtime对session/bytes/queue/idle/resolve/deadline实行冻结
   bounds，saturation/expiry/concurrency/cancel/shutdown无leak或active eviction。
5. **M2-AC-05:** Config/server/observability实现offline zero-resource validation、
   atomic same-port dual bind、closed/redacted telemetry和TCP-only compatibility。
6. **M2-AC-06:** 三方法protocol API到direct UDP echo、focused address/failure/
   backpressure/lifecycle路径在local product seam通过。
7. **M2-AC-07:** `M2-UDP-INT-001..012`在一个authorized exact SHA/run/attempt
   取得12/12+cleanup；任何missing/unavailable evidence为BLOCKED。
8. **M2-AC-08:** Authoritative full、test-budget ratchet、MSRV、Windows/GNU/musl、
   unsafe/license/dependency policy和M0/M1 regression在integration/release
   candidate通过，且v0 non-goals未被加入。

## Dependency and delivery graph

```text
M2-T01 crypto ───────┐
                     ├─ M2-T02 protocol/replay ─┬─ M2-T04 composition
M2-T03 core/runtime ─┘                          └─ M2-T05 qualification impl
                                                  │
M2-T04 ───────────── T05 integration/release ─────┘
```

Initial implementation frontier恰为M2-T01 + M2-T03。T05可在T02后实现，但必须在
T04 integrated后才能integration/release。每票需Architect和QA exact-candidate
full review；execute期间合同冻结。

## Intentional implementation freedom

- replay bitmap/word layout、private type/helper/module names；
- generic runtime内部数据结构和task polling shape；
- equivalent fixture generator language/primitive API，只要source/rights/hash/
  independence不变；
- local test exact file grouping，只要TEST-0003 primary evidence和test-budget不
  退化；
- process adapter CLI spelling，只要只供qualification、不是public inbound。

任何改变wire、numeric bounds、association/window、mutation ordering、default
enablement、public API capability、metrics、12-case/exact-SHA gate或non-goal的
proposal都必须先显式修订批准的合同。
