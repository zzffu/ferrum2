# Existing Linux CPU profiler wrapper audit — 2026-09-05

Full static review: tools/profile-cpu.sh and tests/m0-harness/tests/tooling_profile_cpu.rs. Read root/tools/harness scoped guides, README and docs/README references, docs/performance-evidence.md, historical Windows CPU profiling method, and actual M4 profile-workload parser/ready-file/TCP publication seams. No shell script, profiler, workload, provider, malformed-input probe, or test was executed. No source changes.

## Actual reusable contract

The existing wrapper is **Linux attach-only**. It does not launch Ferrum, accept a command after `--`, start M4, read a ready file, wait for a ready marker, select an active phase, or offer a profiler fallback. Exact accepted arguments:

```text
tools/profile-cpu.sh --scenario <tcp-bulk|udp-small-high> --role <client|server> --pid <positive integer> --duration <1..300> --frequency <1..1000> --output <new directory under repository profiles/>
```

M4 is the existing launch/workload/cleanup owner. Its current minimal local parser accepts:

```text
target/profiling/m4-qualification profile-workload --scenario tcp-bulk --warmup-seconds 5 --active-seconds 120 --ready-file profiles/cpu-tcp-ready.txt
```

`udp-small-high` is the other intersection with the wrapper's closed scenario list. M4 supports additional scenarios (TCP stream/request/scale, DNS, UDP size/direct variants), but this wrapper rejects their names. Do not relabel one as tcp-bulk to get past validation.

M4 bounds are warmup 1..60s, active 10..900s, with tighter scenario-specific limits. Ready-file must be a relative normal-component child of profiles/. It is published atomically with fields `scenario`, `client_pid`, `server_pid`, `warmup_seconds`, `active_seconds`; absent server is written `none`. In TCP and UDP normal scenarios, publication occurs **after warmup and validated worker readiness**, after the common active window has already begun. It is an observation marker, not a release barrier. It is removed during cleanup. There is no M4 `--attach-wait`, `--launch`, `--hold-ready` or wrapper `--ready-file` option.

M4 defaults to product binaries beside its own executable. Explicit binary selection requires both `--repository-root <absolute existing repository>` and `--binary-dir <absolute repository/target/profiling or target/debug>`. A target-triple directory can work through the default executable-adjacent branch; it is not accepted by the explicit path allowlist. Do not accidentally launch target/debug workload and then call the sampled binary a profiling build.

## Concrete invocation shape for later authorized collection (not executed)

On a Linux host with reviewed perf and exact Samply 0.13.1 already available, build the workload and product artifacts together, from the repository root:

```bash
RUSTFLAGS='-C force-frame-pointers=yes' cargo build --workspace --bins --profile profiling --locked
mkdir -p profiles
target/profiling/m4-qualification profile-workload \
  --scenario tcp-bulk --warmup-seconds 5 --active-seconds 120 \
  --ready-file profiles/cpu-tcp-ready.txt \
  > profiles/cpu-tcp-workload.log 2>&1
```

While that foreground M4 command owns and exercises the products, use another terminal at the same repository root. Require a fresh ready path/output name; do not reuse a stale file or source/eval its contents. Read the ready file only after publication, inspect its scenario and selected role, then use the numeric PID it actually contains:

```bash
cat profiles/cpu-tcp-ready.txt
# Substitute the actual client_pid from that file:
tools/profile-cpu.sh --scenario tcp-bulk --role client \
  --pid <client_pid> --duration 30 --frequency 99 \
  --output profiles/cpu-tcp-client-01
```

Angle-bracket PID above is a substitution placeholder, not literal shell syntax. Invoke the wrapper promptly after the fresh marker appears. Wait for the M4 command to finish and retain its exit status and correctness/cleanup output alongside CPU evidence. For server profiling, repeat a fresh equivalent workload and choose its `server_pid` with `--role server`; this avoids mixing simultaneous profiler interference into a role comparison. For UDP, replace `tcp-bulk` with `udp-small-high` in both commands and use separate new files/directories.

The wrapper runs **perf stat for duration, then Samply for duration**, sequentially, plus preflight and stop grace. A 30s invocation therefore needs more than 60s of remaining M4 active life. The 120s active example leaves practical headroom but is not a guarantee because preflight has no absolute bound (CPU-2). Starting a 30s wrapper within a 30s M4 active window is incorrect. No ready handshake pauses the workload while profiler setup runs; no recorded sample-window timestamps prove full overlap. This overlap must be verified from collection evidence, not inferred from identical duration flags.

`[profile.profiling]` in Cargo.toml inherits release, uses debug=1 and strip=none. It prepares optimized binaries with symbols; it collects **no CPU samples** by itself. The RUSTFLAGS above additionally requests frame pointers. That flag must be identical in compared builds. Actual samples are produced by `samply record`, while `perf stat` produces aggregate counters rather than call stacks. Preserve matching executable/debug artifacts; do not rebuild them before symbol analysis. The wrapper currently does not copy symbols or verify unwind quality.

For a performance adoption decision, use the existing performance_candidate controller's plan-bound M4 JSONL evidence. M4 `--output` is not a standalone log option: it requires the complete raw-identity argument set (parent/candidate/member/pair/order/build-profile/unit/runner-image plus four producer/controller/recipe/bundle digests). `--build-profile` values in that raw contract are current/thin/fat/fat-cgu1/source-normalized, not Cargo's literal profiling name. Do not hand-fill fake identity fields. CPU attach runs are diagnostic trials with observer overhead; separately run the existing unprofiled paired qualification for no-regression evidence.

## Findings

### CPU-1 / P2 — Recorded source/build/workload identity is not bound to the attached executable

Locations: profile-cpu.sh:142–145, :196–198, :248–266, :291–301.

Fact: wrapper records its repository HEAD/tree and hardcodes build_profile=profiling and load=profile-workload. verify_target checks only live PID, executable basename ferrum2-client/server, /proc PID directory identity+start time, and executable device/inode. It does not compare /proc/PID/exe bytes with a recorded candidate binary hash, expected artifact path, build flags, or M4 ready-file/workload identity. Any stable same-name build can pass. It records ELF build ID (one required) but not SHA-256, and PID/start/inode tuple is checked internally but not persisted.

Impact: a PASS collection can be attributed to the wrong checkout/profile/workload. Worktree dirtiness is recorded but not rejected. This is static contract evidence; no wrong-target attachment was attempted.

Fix direction: require an explicit M4 ready/identity linkage and expected binary artifact/hash; preserve process start identity, resolved artifact identity, build flags and symbol identity in metadata. Bind sampled binary hash to M4/controller evidence. Do not mistake ELF build ID or basename alone for source provenance.

### CPU-2 / P2 — Duration bounds do not bound all tool lifetime or reap paths

Locations: profile-cpu.sh:33–46, :67–83, :142–145, :208–245, :280–307.

Fact: only the Samply record stage uses external timeout (INT at duration, KILL after 5s). git, rustc/cargo/uname, perf version/list/attach preflight and perf stat are ordinary foreground commands without overall timeout. perf stat's child sleep limits the intended measurement, not arbitrary recorder startup/hang. run_with_bounded_stderr waits for its pipe-drain coprocess without deadline. EXIT trap only writes metadata; it does not explicitly terminate/reap active collector/sink processes on interruption. Preflight stdout files are not size-capped.

Impact: a hung tool or surviving stderr writer can exceed duration and block stage completion; interruption lacks a proved cleanup transaction. Do not claim a reproduced orphan or leak; current normal real-tool behavior was not run.

Fix direction: one absolute per-stage/run process owner, bounded stdout/stderr drains, closed signal handling, and verified kill/reap before final result. Keep Ferrum/M4 target ownership separate: stopping profiler helpers must not kill unrelated product processes. Extend the existing fake-tool test only during implementation, including normal interruption and pipe completion.

### CPU-3 / P2 — PASS checks file presence, not usable counters or sampled stacks

Locations: profile-cpu.sh:311–326; tooling_profile_cpu.rs fake tool output and success assertions.

Fact: perf success requires nonempty file, 0600 mode and absence of literal `<not supported>`/`<not counted>`. It does not require each requested event, finite numeric observations or useful enabled/running coverage. Samply success requires only nonempty file and 0600 mode; no gzip/JSON/schema, target threads, sample count, lost-data or stack/symbol quality validation. The existing fake Samply intentionally writes plain `fake-profile` text to samply.json.gz and the wrapper marks it PASS. This is appropriate for testing control flow but cannot demonstrate valid CPU samples.

Impact: collector process success can be confused with useful profiling evidence. Fix direction: distinguish collection-completed from analysis-qualified; parse exact event/sample artifact contracts and require the intended target/window plus nonzero useful samples, retaining loss/unknown-frame evidence. No real profiler artifact was validated in this audit.

### CPU-4 / P3 — Ready-window coordination is manual and two-stage overlap is unproven

Locations: profile-cpu.sh:305–320; M4 profile_tcp.rs:163–199; profile_contract.rs:611–642.

Fact: wrapper does not consume the marker or record stage start/end times; M4 starts active phase before marker publication. perf and samples occupy different sequential intervals. A target can remain live during drain/cleanup long enough that final PID checks pass after active traffic has stopped.

Fix direction: bind marker and monotonic window metadata to each collector stage, size active lifetime explicitly, and mark out-of-window evidence unusable. Keep perf/Samply sequencing documented; do not pretend their aggregate counters are simultaneous with samples. A separate profiling coordinator may compose existing owners without creating another workload implementation.

### CPU-5 / P3 — Test launcher is itself unbounded and coverage is narrower than recorder correctness

Location: tooling_profile_cpu.rs:75–97 and :121–205.

Fact: test is Linux-only, injects fake tools through child Command.env and does not mutate parent PATH. It tests bounds syntax (including integer overflow), private modes, refusal of existing/outside output, stage results, Samply INT delivery and unsupported perf failure. Command.output has no enclosing deadline/reap owner. It does not test actual artifact validity, target mismatch/reuse, abnormal command duration, complete perf event table, wrapper TERM cleanup, or stage/active overlap. Those are coverage gaps, not a claim the fake test is a real profiler.

Fix direction: reuse bounded harness command ownership; add focused contracts for CPU-1/2/3 while preserving fake tools and no real profiling in ordinary discovery.

## Preserved behavior and permission boundary

- Linux-only check, required command discovery, exact Samply 0.13.1 version and required CLI option checks are explicit. No automatic perf-to-Samply or PMU-to-software fallback exists. Unsupported/missing events or perf attach permission failure end the run before Samply. Do not report a fallback that the code does not implement.
- No sudo, sysctl, perf_event_paranoid adjustment, driver change or privilege escalation occurs. The host must already permit the requested attachment/events. WSL availability/PMU permission is an environment condition; use a suitable native Linux runner when needed rather than changing safety policy silently.
- PID checks before/after each measurement reject process replacement and executable-inode change during normal stage boundaries; target is not deliberately signalled. This is stronger than only kill -0, but not full provenance as CPU-1 explains.
- Output must be a new canonical child below a real repository profiles directory, enforced mode 0700; metadata/stage/main artifacts must be 0600. Stderr drains are capped at 64 KiB and continue draining after cap. Stage STARTED/PASS/FAIL and final result preserve failures after output creation. Early command/path checks before output creation have no artifact directory; that limitation should remain explicit.
- README/docs index routes users to performance-evidence and the historical Windows Confirm/CPU report; no current dedicated Linux wrapper walkthrough was found in those entry points. The historical WPR/xperf/EXE-PDB method is separate from this Linux wrapper and its timings/results cannot validate a new Linux run.

Coverage and execution status are recorded in cpu-profiler-coverage.json. Static only; no new execution evidence or performance claim.
