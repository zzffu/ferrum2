# SPEC-0005 — M4 performance, resource, and v0 preview qualification

- Status: approved
- Milestone: M4
- Baseline: `701925681df78ad83076ed67863bf4fecf46f77c`
- Related contracts: ADR-0016, ADR-0017, ADR-0024, SPEC-0002, SPEC-0004
- Test plan: `docs/test-plans/TEST-0005-m4-performance-resource-preview-qualification.md`
- Tickets: M4-T01, M4-THP-PROFILE-001, M4-QUALITY-PORT-LOCK-001,
  M4-TCP-NODELAY-001, M4-T02

## Scope

M4 adds one reproducible qualification driver around the existing release binaries in
the dedicated non-published `tools/ferrum2-m4-qualification` workspace package.
It measures a diagnostic TCP baseline against the already-pinned shadowsocks-rust
release, proves bounded 10k-idle resource stability, and reuses the existing full,
interop, and native-platform gates for same-commit preview qualification.

Current seams already cover the required path:

- `crates/ferrum2-config/src/lib.rs` accepts up to 65,535 TCP connections and a
  24-hour idle timeout;
- `ferrum2_tcp_connections_active` exposes the production active-flow count;
- `tests/m0-harness/src/local_support/mod.rs` provides the established bounded child,
  SOCKS, metrics, and cleanup patterns used by repository qualification code;
- `tests/interop/versions.toml` pins shadowsocks-rust `1.24.0` and its GNU asset hash;
- `.github/workflows/m0.yml` already converges full validation, TCP/UDP `24/24`, and
  three native targets on one SHA and is the only hosted workflow M4 extends.

## Selected hosted execution profile

`M4-GHA-01` is one fresh GitHub-hosted VM allocated to the `performance` job in
`.github/workflows/m0.yml`. Formal throughput and resource evidence comes only from
that job; local Windows and WSL2 invocations are diagnostic and cannot substitute.

| Field | Fixed value |
|---|---|
| Provider / workflow / job | GitHub Actions; `.github/workflows/m0.yml`; job ID and name `performance` |
| Runner | GitHub-hosted standard `ubuntu-24.04`; `RUNNER_OS=Linux`; `RUNNER_ARCH=X64`; `ImageOS=ubuntu24` |
| Runtime class | At least 4 logical CPUs, 15,000,000 KiB RAM, and 6,000,000 KiB runner-temp free; `nofile` soft limit set to 65,536 |
| Build toolchain | Rust `1.97.1`; locked workspace release defaults; actual C compiler and linker recorded |
| Reference | shadowsocks-rust `1.24.0`, GNU asset SHA-256 from `versions.toml` |

GitHub's [hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
currently documents the selected public-repository runner class as a fresh x64 VM with
4 vCPUs and 16 GB RAM. The job preflight above remains authoritative if the provider
changes that class. `GITHUB_SHA`, run ID/attempt, event, image version, actual kernel,
CPU model/count, memory, compiler, linker, reference SHA-256, and configuration hashes
are repeated in the generated record. CPU model, kernel, and image version are recorded
rather than pinned because GitHub-hosted images and hardware can roll; both throughput
topologies run in the same job/VM to bound that variation.

## Requirements

### M4-MUST-01 — fail-closed identity and cleanup

The hosted job and driver MUST reject a dirty checkout, a Git SHA other than
`GITHUB_SHA`, a missing or mismatched `M4-GHA-01` identity/capacity field, an unverified
reference binary, malformed or missing metrics, an early child exit, a timeout, a
partial sample set, or incomplete cleanup. Every child, listener, target stream, load
worker, and temporary file has a bounded owner and reap path. Output contains no PSK,
key material, destination, or unbounded child log; the committed repository contains
no raw result.

### M4-MUST-02 — comparable TCP throughput baseline

Both topologies run sequentially in one `performance` job and use their release client
and server, loopback SOCKS5 and target endpoints, TCP only,
`2022-blake3-aes-128-gcm`, the repository synthetic AES-128 PSK,
no verbose/debug flags, bounded child output, and no metrics endpoint. Ferrum2 uses
`max_connections = 12000`, `listen_backlog = 65535`, and
`idle_timeout_ms = 3600000`; shadowsocks-rust uses the equivalent fixed `tcp_only`
client/server configuration already exercised by the interop harness.

One shared driver and target run eight parallel SOCKS-established streams with a
fixed 64 KiB payload. Each trial warms for 10 seconds and then measures 30 seconds of
successfully echoed application payload. There are five measured trials per topology,
in fixed alternating order `F,R,R,F,F,R,R,F,F,R`; startup and warm-up bytes are not
counted, and no trial is discarded.

The record MUST contain every trial's bytes, elapsed monotonic time, and aggregate
bytes/second, plus each topology's positive five-value median,
`ferrum_median / reference_median`, and the signed percentage difference. The numeric
ratio is diagnostic only: every finite non-negative ratio is accepted and no
optimization follows automatically.

### M4-MUST-03 — bounded 10k-idle resource qualification

After the throughput trials in the same job, the driver starts the ferrum2 release
client/server with UDP disabled, error-only logging, loopback metrics endpoints, the
fixed runtime values above, and one holding TCP target. It completes 10,000 SOCKS
handshakes with at most 256 setup operations in flight, retains all application and
target streams, and requires both production active-connection gauges to equal 10,000
before stabilization starts.

Before starting resource qualification, the selected hosted profile MUST bind
`/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none` to exact `0`. This
mutation occurs only after throughput completion and validation. The main step MUST
first read a canonical unsigned decimal original (`0` or `[1-9][0-9]*`), durably arm
restoration state, use the
fixed value through stdin with non-interactive `sudo -n`, and immediately require
exact `0` readback. It MUST arm `EXIT` and `TERM` restoration; an independent
`if: always()` step is the backstop. Process reap, restore, exact restore readback, and
evidence deletion are each attempted even if another cleanup action fails. Cleanup
failure remains explicit and cannot replace the primary qualification failure.

Runner loss or `SIGKILL` makes restoration unprovable and therefore invalidates the
run; disposal of the fresh temporary VM is containment only, not evidence of successful
restoration. The profile assumes the dedicated runner has no other authorized
privileged mutator. Apply/readback and the final driver check bound interference but do
not claim to eliminate a transient TOCTOU.

After `M4-GHA-01` hosted identity validation and before creating evidence or temporary
state, listeners, configuration, or children, the driver MUST reject unavailable,
malformed, or nonzero knob state with the exact static redacted errors
`THP max_ptes_none profile is unavailable`,
`THP max_ptes_none profile is malformed`, and
`THP max_ptes_none profile is not zero`, respectively. These errors contain neither
path nor value. It MUST require exact `0` again after exact drain and before emitting
PASS. The generated `resource_profile` MUST record `max_ptes_none=0`.

After five stable minutes, the driver records exactly 180 samples at 10-second
intervals. Each sample contains:

- both `ferrum2_tcp_connections_active` values;
- both process `/proc/<pid>/fd` counts and `/proc/<pid>/task` counts; and
- both process RSS values from `/proc/<pid>/status`.

Each sample reads `/proc` before opening its metrics scrape so the observation
connection cannot perturb the fd tuple; the `/proc/<pid>/task` value is explicitly the
Linux task/thread count. The existing production-used `OwnerRegistry` suites remain
the async-task ownership evidence.

Every non-RSS owner/task tuple MUST equal the first stable tuple, including active
gauges of exactly 10,000. The 180 RSS values form six consecutive 30-sample windows;
for each binary, every window median MUST be no more than 105% of its first-window
median using exact integer comparison.

The THP binding is a selected conformance profile amendment, not a product fix or a
relaxed resource gate. Setup concurrency 256, five-minute stabilization, exactly 180
10-second samples, six 30-sample windows, 105%, active/fd/task invariants, the absolute
two-minute drain deadline, and the throughput profile remain unchanged. No `VmSize`
rule, extra stabilization, allocator/buffer/protocol change, or dependency is added.
Absolute RSS results are comparable only when the named selected profile is also
recorded.

After the driver closes all application streams, the target MUST observe closure and,
within one absolute two-minute deadline, both active gauges, fd counts, and task counts
MUST exactly equal their pre-load baselines while both binaries remain alive. This is
the only M4 resource qualification; existing M3 owner-registry tests remain the
internal secondary evidence and no production debug surface is added.

### M4-MUST-04 — generated evidence boundary

Hosted raw JSON Lines records, downloaded references, and captured logs live only below
`$RUNNER_TEMP/m4/`; local diagnostic self-check output lives only below ignored
`target/m4/`. The hosted job prints one bounded redacted summary, deletes its temporary
tree, and uploads no raw artifact. A durable closeout may record the exact SHA, hosted
profile, medians, ratio, RSS-window verdicts, sample counts, command exits, and run
identity, but MUST NOT commit raw logs, downloaded references, binaries, packet
captures, or benchmark output.

### M4-MUST-05 — one-commit v0 preview convergence

M4 accepts one exact product commit only when one separately authorized `push` run and
one attempt of `.github/workflows/m0.yml` has:

- `performance` passing MUST-01 through MUST-04 on one `M4-GHA-01` VM;
- `quality` passing the Full validation and test-budget gates;
- `interop` passing TCP and UDP `12/12` each with cleanup;
- Windows MSVC, Linux GNU, and Linux musl `platform` rows passing;
- the existing final `qualification` job passing; and
- zero unresolved P0/P1 blocker or blocking review finding.

Different commits, workflow attempts, partial runs, skipped rows, historical evidence,
local/WSL2 results, or provider/setup unavailability cannot be combined into PASS. T02
requires explicit remote authorization; M4 performs no tag, release, upload, or
publication.

## Non-goals

- A throughput floor, performance certification, optimization ticket, profiler work,
  custom allocator, unsafe code, or changed security/backpressure behavior.
- More methods, reference implementations, load shapes, runner classes, or soaks.
- Treating WSL2 or the historical failed `a53a5d7` run as passing evidence, or claiming
  that the hosted allocator/kernel causal path has been proved.
- New metrics, management/debug endpoints, product configuration, or dependencies.
- Packaging, signing, publication, SIP023, multi-user, public UDP inbound, routing,
  DNS proxying, chaining, hot reload, TUN, transparent proxying, or `io_uring`.

## Implementation freedom

The driver may organize private helpers and output fields differently inside the
dedicated tools package if one bounded Cargo binary and the single hosted
`performance` job prove the same claims. Equivalent
evidence substitution follows ADR-0016 and must be approved before execution; it
cannot weaken the hosted-only boundary, sample counts, timing, exact drain, same-SHA,
or fail-closed outcomes.
