# ADR-0015: M0 Unix listener restart and exact rebind evidence

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`ADR-0005`、`ADR-0011`；
  `SPEC-0001`；`TEST-0001`；M0-T07、M0-T08

本 ADR 仅部分取代 ADR-0011 的 M0-LIFE-005 exact-rebind probe 与 harness
dependency/lock allowlist；ADR-0011 的其余 evidence、ownership、native request
generation 和 policy 决定继续规范。ADR-0016 将具体probe实现与test-only
dependency allowlist定义为selected conformance profile；immediate restart、
live-owner exclusion、Unix/Windows安全边界继续是规范性不变量。
ADR-0017 进一步取代本 ADR 为旧 11-job profile规定的exact filters、test-count、
linker-help和workflow self-audit修复；listener行为与lifecycle结果不变。

## Context and problem

Exact integration commit
`51fb7327af966cfc3f4a49058ea6bf2284009dcf` passed its local integration,
Architect and QA gates, but GitHub Actions run `30301746374` exposed a Linux
listener-restart defect. The first M0-LIFE-005 cycle completed real proxy and
metrics TCP connections, reaped the child, and then could not bind the same
addresses because the prior TCP lifecycle still occupied kernel state. The same
failure independently blocked host-quick, MSRV, focused lifecycle, and full
integration jobs; later poisoned-lock failures were derivative.

Both binaries create proxy and metrics listeners through `tokio::net::TcpSocket`.
Unlike Tokio's convenience `TcpListener::bind` on Unix, that constructor does not
enable address reuse. A sleep, retry, random replacement port, or weakened
rebind assertion would hide rather than satisfy ADR-0005's deterministic
restart contract. Enabling address reuse on Windows is also not an equivalent
choice: Tokio documents different Windows port-sharing and hijack semantics.

The black-box harness currently checks rebind with
`std::net::TcpListener::bind`. It therefore cannot mirror the selected
platform policy. ADR-0011 also freezes the harness direct dev-dependency set at
five packages, so using the already workspace-pinned `socket2` package requires
an explicit amendment.

## Decision drivers and invariants

- After a ferrum2 listener has fully terminated, Unix must permit immediate
  restart on the exact configured proxy or metrics address, including after real
  accepted connections.
- A still-live listener must continue to exclude a second listener on the same
  address. M0 does not permit port sharing or takeover.
- Windows retains its default exclusive bind behavior; no Windows
  `SO_REUSEADDR` opt-in is allowed.
- The change must not affect accepted or outbound sockets, relay/half-close
  behavior, SIP022 wire state, configuration, CLI, public API, metrics schema,
  or operator surface.
- Test evidence must use an OS-correct bind-and-listen probe and must preserve an
  explicit live-owner collision negative case.
- No new package, dependency version, source, checksum, unsafe code, or
  production dependency edge may be introduced.

## Options considered

### Option A: platform-specific listener reuse plus matching exact probe

Set address reuse before bind on Unix listener sockets only. Use `socket2` in the
test-only harness to apply the same Unix/default-Windows policy, then both bind
and listen on each original address. Keep a live owner during a negative
regression to prove a second listener still fails.

### Option B: delay or retry until kernel state expires

Rejected. Timing depends on host kernel state, makes the 100-cycle gate flaky,
and no longer proves immediate restart.

### Option C: select fresh ports or relax exact rebind

Rejected. It contradicts M0-LIFE-005 and cannot detect leaked or incompletely
terminated listeners.

### Option D: enable reuse on every platform or add `SO_REUSEPORT`

Rejected. Windows address-reuse semantics can allow unwanted takeover, while
`SO_REUSEPORT` deliberately permits multiple live listeners. Neither behavior is
part of M0.

## Decision

Choose Option A.

Client 和 server 没有跨 binary shared constructor。各自的 binary-private
`bind_listener` 都必须按以下顺序创建 proxy 或 metrics listener：

1. Create the IPv4 `TcpSocket`.
2. On Unix only, call `set_reuseaddr(true)` before `bind`.
3. On Windows, do not set address reuse.
4. Bind the validated configured address.
5. Proxy 使用 validated configured `listen_backlog`；metrics 保持现有固定
   backlog 16，然后调用 `listen`。

`new_v4`、`set_reuseaddr`、`bind` 或 `listen` 的任何失败都继续映射为现有
`RunError::Listener`，不得增加新 error、重试或 fallback。

No accepted socket, outbound connector, direct target socket, or runtime/public
interface changes. `SO_REUSEPORT` remains forbidden. A live listener owning the
same address must still cause startup to fail through the existing closed error
path.

M0-LIFE-005's exact rebind helper must create a stream socket, apply
`SO_REUSEADDR` on Unix only, bind the original address, and call `listen`; a
successful bind without listen is insufficient evidence. 所有由 harness 创建、在
接受流量后还必须 exact rebind 的 listener，包括 target 以及 collision mutation
使用的 foreign proxy/metrics listener，都必须在首次 bind/listen 时就使用这个
helper；不能只对最终 probe 启用 reuse。

Live-owner regression 的 incumbent 必须先用该 helper 成功 bind/listen 并保持
存活；contender 再用相同 OS policy 的 helper 尝试同一地址，并且必须在 bind 或
listen 失败。该回归在 Unix 与 Windows 都 required，证明允许 Unix restart 不等于
允许两个 live listeners 共存。

ADR-0011's harness exception is amended as follows:

- `tests/m0-harness/Cargo.toml` gains exactly
  `socket2.workspace = true` under `[dev-dependencies]`;
- the exact direct dev-dependency set becomes `aes-gcm`, `blake3`, `hex`,
  `serde_json`, `socket2`, and `tempfile`;
- `socket2` remains workspace-pinned at `=0.6.5`;
- `Cargo.lock` may change only by adding `"socket2"` to the
  `ferrum2-m0-harness` dependency list; package count and every package identity,
  source, checksum, version, and resolved production feature set remain
  unchanged;
- the harness still cannot depend on any `ferrum2-*` package.

### Hosted evidence-script portability

本节记录旧11-job profile的历史修复合同；ADR-0017接受后由其结果导向profile整体
取代，不再逐项实现下列filter/linker/scope mechanics。

Run `30301746374` 另有四项 T08-owned evidence-script defects。它们不改变上述
socket decision，但修复后的单一 SHA 必须同时满足：

1. `m0-local-e2e` 对
   `valid_client_and_server_configs_have_exact_offline_output` 的 list 与 execution
   均使用 full-name libtest `--exact`，并保留 exact count 1 检查；不能让
   `invalid_matrix_is_redacted_and_uses_exit_two` 进入该 selection。
2. `m0-security` 对
   `exact_invalid_does_not_poison_then_duplicate_is_rejected` 使用同样的
   full-name `--exact` 与 exact count 1 检查；不能匹配包含 `exactly` 的并发测试。
3. `m0-linux-gnu` 和 `m0-linux-musl` 取得 compiler-reported linker 后，绝对路径
   直接进入 canonicalization，bare name 必须先通过 `command -v` 解析；结果随后
   canonicalize、检查为 executable，并实际运行 `--version`。不得把 bare `ld`
   相对 checkout 解析，也不得只验证路径字符串非空。
4. `m0-windows-msvc` 必须验证解析出的 `link.exe` 存在并可执行，捕获 `link /?`
   的合并输出与 exit；help exit 只接受 `{0, 1}`，且输出必须匹配 Microsoft
   linker/version banner。缺失 executable、其他 exit、缺失 banner 或探针异常
   都失败。步骤最终必须显式恢复成功状态，不能让已验证的 help exit 1 污染后续
   PowerShell step result。

`scope_audit` 必须同步 closed workflow blob、exact command allocation 与对应的
anti-regression assertions。上述修复不得改变 job IDs/names、runner matrix、
triggers、permissions、action full-SHA pins、timeouts、toolchains、test semantics
或 product behavior；不得删除 nonzero/exact count、executable/version 或
fail-closed checks。

## Consequences and tradeoffs

### Positive

- Unix restart semantics now satisfy the already approved exact-address
  lifecycle contract after real TCP traffic.
- The harness observes the same platform policy through a bind-and-listen
  boundary and still detects a live owner.
- Windows port ownership remains conservative.
- The new harness edge reuses an existing pinned workspace package and does not
  alter production dependency graphs.

### Negative

- Client and server listener construction contains a small platform-specific
  branch.
- Exact rebind evidence can no longer use only the standard-library convenience
  bind.
- ADR-0011's previously closed five-package harness allowlist and lock edge must
  be revised and guarded by mutation tests.

## Compatibility and upstream divergence

This decision changes no Shadowsocks, SOCKS5, configuration, metrics, or public
Rust contract. The only intended observable change is that a fully terminated
Unix ferrum2 listener can be restarted immediately on the same address. A live
owner still blocks startup. Windows behavior is unchanged. The workflow
invocation/linker repairs remain evidence-script portability corrections under
ADR-0007 and do not alter product behavior.

## Migration and rollback

There is no persisted-state, wire, or configuration migration. Rollback must be
atomic across both binary Unix listener options, the harness helper and every
initial listener migrated to it, the manifest/lock edge, workspace/scope policy,
and synchronized SPEC/TEST text. Rolling back only production or only evidence
would make them diverge and is not allowed. A complete rollback restores the
demonstrated Linux restart failure and therefore restores M0 to BLOCKED.

## Verification plan

- Before the implementation change, reproduce the Linux exact-rebind failure
  after a real process cycle.
- Run exactly 100 real-process M0-LIFE-005 cycles, 20 in each approved category,
  and prove after every cycle that:
  - every child is boundedly reaped;
  - the exact proxy, metrics, and target addresses bind and listen immediately;
  - the temporary path is absent;
  - harness and production ownership evidence returns to baseline.
- Keep a same-policy helper listener live and prove a second same-policy
  bind-and-listen attempt on its exact address fails on Unix and Windows.
- Mutate away the Unix production `set_reuseaddr`, the helper's Unix reuse
  option, or its `listen` call and require focused evidence to fail.
- Prove manifest and lock policy for LF/CRLF, exact six dev edges, no
  `ferrum2-*` edge, unchanged package identities, and unchanged production
  normal/build trees.
- Re-run current and Rust 1.85.0 focused lifecycle, quick, full, scope, native
  platform, and same-SHA integration gates.
- In `m0-windows-msvc`, prove `{0,1}` plus Microsoft banner handling, and
  mutation-fail for missing executable, exit outside the allowlist, or missing
  banner. In GNU/musl, prove absolute and bare-name linker resolution and
  mutation-fail for unresolved/non-executable linkers.
- List and execute each corrected config/replay filter with full-name `--exact`
  and exact count 1.
- After local integration, Architect and QA pass and a separately authorized
  push occurs, require a new exact integration SHA to pass all eleven jobs in
  one GitHub Actions run/attempt; run `30301746374` remains failed evidence and
  cannot be combined with the new run.

## References

- `ADR-0005`: runtime listener ownership and deterministic lifecycle evidence.
- `ADR-0011`: exact black-box lifecycle and harness dependency policy.
- `ADR-0007`: exact pushed-SHA GitHub Actions evidence contract.
- `SPEC-0001` AC-08/AC-10.
- `TEST-0001` M0-LIFE-005 and M0-CI-001～006.
