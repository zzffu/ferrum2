# M4 qualification tooling: complete static engineering audit

Snapshot: 2fb0dd4a9099837b81586a11fba4d265777674bb; 2026-09-05. Scope: all 35 Rust source files under tools/ferrum2-m4-qualification/src. Coverage JSON records each full source read, including executable self-check owners. This is not a benchmark result or a proof of no regression.

Instructions read: root AGENTS.md, tools/AGENTS.md, tools/ferrum2-m4-qualification/AGENTS.md. Documentation reviewed: docs/performance-evidence.md; relevant README.md/docs/README.md entry-point references. There is no package README.md. CI/consumer interface checked: performance-candidate.yml run_profile invocation; Linux trial schema/identity/work checks; Windows trial CPU-window/work checks. Controller-wide and PowerShell source review belongs to root, not this coverage claim.

No production edits, benchmarks, privileged workloads, client test binary, new fault injection, or resource-exhaustion/deadlock reproduction were run. Findings below are static source facts and explicit conditional schedules. Dynamic validation is pending; root instructed no further abnormal reproduction after automatic review interrupted other audit groups. Previously completed platform safe suites are not evidence for this tool.

## Findings

### M4-01 — P1: setup rollback can join a worker blocked on its retained result receiver

Location: resource_sampling.rs:39-88, particularly :56 and :65-67. Contract: every spawned worker must be stopped and reaped on every failure; bounded channels must not make rollback depend on the abandoned consumer.

Fact/time line: (1) coordinator owns the only receiver and an original sender for sync_channel(SETUP_WORKERS); each started worker owns another sender and loops over up to 10000 session indices. (2) Before coordinator finishes spawning, workers may produce more than channel capacity results; a worker can block inside send at :56. (3) a later spawn returns Err; coordinator writes the index stop flag and drops only the original sender. (4) coordinator joins all earlier workers while still owning receiver and without receiving. (5) a blocked sender needs a receive or receiver drop; worker cannot observe the index flag until send returns; receiver stays alive until join returns. That is a source-proven wait cycle conditional on channel saturation before spawn failure, not a dynamically reproduced incident. The capacity equals worker count, not total results, so repeated production permits this schedule.

Impact: resource qualification can hang during cleanup instead of producing a bounded failure. Direction: retire/drop receiver before join on abandonment, keep first error while joining every worker, centralize this setup ownership with the already-correct receiver retirement pattern in tcp_scale/setup.rs:64-70. Validation pending: bounded injected spawn failure with deterministic channel occupancy and join completion assertion; do not run under current instruction.

### M4-02 — P2: DNS responder loses worker ownership on construction/finish errors

Location: profile_dns.rs:41-98. Contract: setup is transactional and all worker handles remain owned until joined.

Fact: try_clone and set_read_timeout use ? at :50-53 after earlier iterations may have spawned workers. Until Self is constructed, workers is a bare Vec; return drops/detaches handles without setting the shared stop flag. Its responder loops therefore retain their sockets/Arc state until process termination. The explicit spawn-error branch correctly stops/joins, but does not cover these preceding errors. finish takes the entire vector at :82, then join_worker(worker)?? or checked_add? can return before later handles are joined; Drop then sees an empty vector. In that second case stop is already set, so eventual exit is expected, but synchronous reap is not proved.

Direction: create a fully owned responder guard before the fallible loop; finish must collect the first error and continue reaping all handles. Validation pending: injected clone/configuration/worker-result errors and observable zero owned workers/socket rebind, with bounded execution.

### M4-03 — P2: schema rejection probe bypasses bounded child capture and timeout ownership

Location: resource.rs:301-353, Command::output at :331. Contract: all children have bounded output, bounded lifetime, reap, and evidence on error.

Fact: the rejection probe directly waits with output(), collecting stdout/stderr to memory, before checking the exit contract. A candidate that fails to terminate or writes excessively bypasses ProcessGuard's capped output and supervised polling. Historical success of schema rejection is not a bound on candidate behavior. No such candidate was executed.

Direction: route this probe through the existing supervised child owner with an explicit rejection deadline and bounded capture; make failure diagnostics retain identity and cleanup. Validation pending: ordinary bounded supervisor tests when authorized, plus the normal self-check/CLI gates.

### M4-04 — P2: SOCKS deadline is an inactivity timeout and returned streams can have unbounded writes

Location: process_support.rs:166-196; resource.rs:416. Contract: named operation deadlines must bound the complete operation and every resource scenario must retain I/O bounds.

Fact: socks_connect computes remaining once before connect, reuses it for subsequent reads/writes, and read_exact/write_all can perform multiple successful partial operations. It does not re-evaluate the deadline between stages or partial progress. It then clears both timeouts. The M14 TCP resource path restores a read timeout but writes its payload at :416 without restoring a write timeout. Impact: slow progress or stalled write can exceed the intended test bound; controller/job expiry is only an outer escape, not this function's deadline.

Direction: use complete-operation deadline-aware read/write loops, as tcp_scale already does, and configure each returned stream before any work. Validation pending: bounded fake I/O deadline and partial-progress checks, with no actual adversarial network run in this audit.

### M4-05 — P2: output containment is validated after creating the requested parent

Location: profile_contract.rs:666-696; profile_output.rs:44. Contract: evidence paths stay under repository profiles/ and rejected paths must not mutate unrelated directories.

Fact: resolve_profile_ready_file calls create_dir_all(parent) at :680 before canonical containment at :682. It is used for raw --output as well as validated ready paths. An out-of-root output parent can be created before the function rejects it; symlinked intermediate parents also must be resolved before mutation. No path escape was executed. This is a local CLI mutation ordering defect, not a remotely reachable product vulnerability.

Direction: validate lexical output components and canonical existing ancestor containment before creating directories, then revalidate the created path. Validation pending: temporary-directory behavioral assertions that rejection leaves outside parents absent.

### M4-06 — P2: Windows fairness counts tail work against a shorter nominal denominator

Location: windows_tun/workload.rs:255-397, loop :310 and metric :397. Contract: throughput numerator and elapsed denominator describe the same active window; paired CPU/work evidence uses compatible successful work.

Fact: each fairness worker starts an exchange while now < deadline, then counts bytes even if completion is after deadline. Aggregate throughput divides all those bytes by active, not measured completion elapsed. In contrast tcp_single uses elapsed and Linux transfer_is_measured excludes out-of-window completions. Up to one final transaction per fairness flow can cross the boundary; completion delay and scheduler variance can change its size relative to the nominal window. CPU complete is signaled only after worker joins, so sampling includes the tail while throughput does not extend its denominator.

Impact: short-window fairness throughput/Jain inputs can be biased; the sign and magnitude for a real candidate are not established. Direction: use explicit transaction start/completion admission for the fixed window or a consistently measured extended window, and report window timestamps/tail work separately. Validation pending: pure clock/accounting boundary tests (before/exactly/after deadline), then paired A/A calibration and A/B actual host measurements only through root's authorized runner.

### M4-07 — P2: minimum sample counts extend requested active windows

Location: windows_tun/workload.rs:217 and :886. Contract: quick workload duration is bounded and comparable across candidates; sample coverage failure is explicit.

Fact: TCP request loop continues while deadline has not elapsed OR transactions < TCP_REQUEST_MINIMUM_TRANSACTIONS (1024); UDP continues similarly to UDP_MINIMUM_DATAGRAMS (4096). Therefore configured active seconds are a lower bound, not an upper bound; slow successful responses can keep workloads running well beyond the nominal window. Per-I/O timeout bounds inactivity, not total successful-work duration. Windows trial consumer permits CPU duration up to active+60 seconds, but an even longer workload reaches the outer host timeout instead of a complete producer observation. Outer job containment remains valuable and this finding does not claim the host can run forever.

Direction: cap active duration independently, fail insufficient sample coverage with complete accounting, and state closed-loop sample requirements in the recipe. Validation pending: pure minimum-count/deadline boundary checks and paired calibration, no slow-response reproduction performed.

### M4-08 — P2: DNS profile success validation accepts incomplete response semantics

Location: profile_dns.rs:384-391. Contract: checked_units counts correct successful work, not merely parseable responses with a matching first address.

Fact: success checks ID, response message type, and first answer data A(127.0.0.1). It does not compare expected question/name/type/class, response code/opcode, or exact answer set. A response with the right ID/first A but wrong question or error metadata can pass this local checker. The responder validates requests more narrowly; that does not prove the proxy response preserves semantics.

Direction: define and compare the expected response semantics as a complete object, allowing only fields deliberately excluded from the workload contract. Validation pending: pure response object mutations for question, code, opcode, answer owner and extra answers; no traffic injection performed.

### M4-09 — P2: DNS drain evidence proves stability below a ceiling, not return to baseline

Location: dns_resource.rs:258-309; resource_sampling.rs:187. Contract: evidence naming must distinguish bounded resource retention from drained owners.

Fact: wait_for_dns_drain succeeds after a repeated fd/task tuple remains stable and validate_dns_owner_bound permits idle + DNS_OWNER_DELTA (160) per role. proc-based DNS sampling supplies active=0, making that branch no independent active-owner measurement. Thus a stable retained set within the ceiling can be labeled drain success. Later process termination/rebind can still prove final port cleanup; this finding concerns in-process drain, not a demonstrated resource leak.

Direction: name the existing result bounded/stable, or add an actual baseline/owner-release contract with justified retained infrastructure allowance. Validation pending: complete sample-object checks for stable nonbaseline values and documented intentional retention.

## Architecture and evidence assessment

The current private module tree has clear execution, contract, process, evidence, and TCP-scale owners. No production file exceeds the tool's 1000-line cap; windows_tun/workload.rs is 989 physical lines, so further unrelated growth should move to cohesive TCP/UDP or active-window owners. Do not mechanically split owner state just to meet a count. pub(crate) on many internal Windows/scale fields can generally narrow to parent ownership; this is P3 interface cleanup, not grounds to fragment lifecycle transactions. Known enum matching is largely explicit; string option fallback branches correctly reject unknown inputs. The tool introduces no expanded Windows unsafe exception or new async trait abstraction.

ProcessGuard caps retained capture output and normally kills/waits/joins; its pipe reader threads and wait_child remain dependent on process/pipe EOF after kill. Raw thread::spawn in capture occurs before a complete ProcessGuard is constructed, so spawn-panic ownership deserves design review. No descendant-pipe or thread-spawn failure is dynamically established here. tcp_scale/setup explicitly retires its receiver on rollback and uses deadline-aware I/O; preserve these stronger patterns when consolidating setup behavior.

Linux profile TCP/UDP/DNS count checked completed work with explicit warm/active admission, and scale uses tagged flow/sequence payloads, bounded setup, task ownership, resource samples and cleanup facts. Request latency is closed-loop; it cannot establish open-arrival tail latency or overload service objectives. Reservoir sampling is capped and deterministic; nearest-rank p99 is a sampled estimate, not a confidence interval. Scale RSS peaks are maxima of scheduled observations, not continuous OS high-water measurements; signed touched-memory deltas appropriately preserve decreases/noise. CPU model/count and total machine memory are environment identity, not process CPU or memory measurements.

Linux profile ReadyFile is published after warm_end, while worker active windows already start at warm_end (profile_dns.rs:228-258; analogous TCP/UDP). A profiler attaching after observing ready therefore misses a variable initial interval. The ordinary performance-candidate workflow runs profile-workload synchronously and checks throughput/latency plus identity; it does not collect process CPU in these trial rows. Stage-three CPU attribution needs either a ready/release handshake or an explicitly timestamped sampled subwindow, exact binary/source/profile identities, process roles, workload checked units and capture-loss information. Windows already has ready/release/complete markers and host CPU sampling, but M4-06/07 must be addressed before treating its short window as uniform.

Linux consumer validates trial schema, pair/order/member, source/binary hashes, recipe/controller/bundle identities, units and successful counters. Windows consumer checks topology, CPU sample seconds, failure counter deltas, work and process presence. These are good fail-closed boundaries: a missing/failed trial is not equivalent to a qualified candidate. Producer parse/path/evidence-creation failures can precede any JSONL row, and Windows workload errors commonly exit before an observation is written. Controllers must retain failed invocation identity, exit, bounded stderr, cleanup and missing-observation reason; do not silently discard failed trials or substitute previous successful rows. Full PowerShell/controller verification is root-owned.

The existing throughput reference gate verifies an archive and reported version but should not be mistaken for complete archive-to-executable content binding. Candidate source/binary identities in profile trials are stronger and should remain the architecture for future comparisons.

## Stage-two/three acceptance inputs

1. Fix window/accounting and lifecycle findings before collecting optimization evidence; update the semantic recipe and exact producer/controller manifests when behavior changes.
2. Run ordinary compilation, fmt/clippy and the tool's existing nonprivileged self-check after implementation under the repository test contract. This audit did not execute self-check or benchmarks.
3. Recalibrate A/A noise with the exact producer and recipe. Then collect complete interleaved baseline/candidate pairs for affected workloads and non-target guard scenarios, preserving failed trials. Quick is screening evidence, not an unconditional proof of absence of regression.
4. Separate correctness qualification from performance verdicts. Earlier host eight-check qualification or 128 safe TUN tests cannot replace performance comparisons. Historical TCP 10054/startup.bind failures remain failed evidence, not speedup.
5. For CPU optimization, pair sample attribution with CPU cost per checked work, elapsed window, p99/sample coverage and process memory. Compare the same topology and process roles; hardware/environment identity and sampling uncertainty must be visible.

Every priority above reflects tool correctness/reliability, not an asserted production exploit. Suggested dynamic validation is future work; no blocked reproduction was retried or routed through another mechanism.
