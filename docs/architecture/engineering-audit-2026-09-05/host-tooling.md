# Host tooling independent static audit

Reviewed 2026-09-05 at product HEAD `2fb0dd4a9099837b81586a11fba4d265777674bb`. Scope: every PowerShell/C# module and manifest under `tools/powershell`, the sole `tools/windows-tun/performance` runner, and `tests/platform` native entrypoint/contract plus qualification runner/worker/static tests/fixtures. Applicable root, tools, tests, powershell, windows-tun/performance and platform/config AGENTS were read. Every scoped implementation file was read in full; see `host-tooling-coverage.json`.

No product/tool source was modified, imported, executed or dot-sourced. No runner, benchmark, profiling, privilege-changing command or dynamic failure experiment was run. The only verification beyond reading was a non-executing byte-length/SHA-256 reconstruction of both source manifests: all 10 performance and all 11 qualification members matched. Current source closure matches each import and embedded Add-Type input. Qualification does not invoke the performance public runner; both share ownership/execution/product primitives. Historical live runs are contrary evidence against blanket claims of startup failure, not proof that every branch below is covered.

## Findings

### HT1 — P2: CPU per checked unit drops the measured-window ratio

Locations: `tools/powershell/Ferrum2.Performance/HostProfiles.ps1:12`, `:75`–`:85`; CPU numerator and window collection in `HostExecution.ps1:759`–`:787`, `:836`–`:847`, raw window at `:880`.

Static fact: trial CPU percent is computed from process CPU delta divided by its independently measured `cpu_sample_seconds`. Summary cost ratio is `(candidate_percent / baseline_percent) / (candidate_checked_units / baseline_checked_units)`. This equals the intended CPU-milliseconds-per-checked-unit ratio multiplied by `baseline_window / candidate_window`. It is correct only when those independently measured windows are equal. Marker observation polling, asymmetric sampling and completion waiting make exact equality an unsupported assumption.

Impact: the 2% CPU regression classification can be biased by a window difference even with identical CPU cost per unit. This is an algebraic defect in the reducer; no claim is made that a particular historical verdict crossed the threshold because of it. The raw percent, sample seconds and checked units are retained and permit corrected reanalysis without fabricating new measurements.

Direction: retain actual CPU delta in milliseconds as a first-class trial measurement and divide by checked units, or restore the missing candidate/baseline window multiplier. Report paired normalized cost ratios alongside percent/checked units. Verify with pure fixed observations having unequal sample windows and equal cost; no live run is needed for the arithmetic contract.

### HT2 — P2: zero-residue report exceeds the verified cleanup surface

Locations: `HostOwnership.ps1:587`–`:695`, specifically route deletion `:617`, address deletion `:635`, ledger reset `:688` onward and literal zero report `:758`–`:763`; early record removal in `HostProduct.ps1:135`–`:142`, support-port removal `HostProfiles.ps1:265` and `:319`; qualification's ledger-only final check `HostQualification.ps1:496`.

Static fact: cleanup queries route/address identity before removal but does not read back absence after `Remove-NetRoute`/`Remove-NetIPAddress`. It does read back adapter disappearance and the ports still present in the ledger. Normal product shutdown, however, removes product route and port rows as soon as the main process stops and the adapter disappears, without checking those endpoint identities first. Support shutdown similarly removes support-port rows before final cleanup can query them. Final reports write every remaining counter as literal zero and qualification checks the emptied ledger.

Impact: successful remove commands and parent-process exit support an expectation of cleanup, but the recorded report does not independently establish all five zero-residue claims. This is an evidence-strength gap, not proof of actual host residue. Historical runner JSON reports contain zero counters; this audit does not establish independent post-removal route/address readback for those runs.

Direction: retain immutable expected identities until after bounded absence readback, then retire the ledger rows. Have the readback result produce the residue counts, including product/support ports, routes and addresses. Preserve the fail-closed identity checks; never remove an unrelated replacement to make a zero count. Prove cleanup contracts via reviewed static/pure seams before the dedicated authorized live path resumes.

### HT3 — P2: timeout recovery logs are deleted while the failure points to them

Locations: `tests/platform/run_windows_tun_qualification_host.ps1:109`–`:131`, `:188`–`:204`.

Static fact: timeout recovery writes `recovery.stdout.log` and `recovery.stderr.log` under the transient supervisor root. On recovery failure, the thrown error points to the recovery stderr path. The finally block copies only worker stdout/stderr to external evidence and recursively removes the supervisor root. Recovery logs therefore disappear, including the file named in the error. When evidence directory never became available, worker logs also have no persistent destination.

Impact: the most consequential timeout/recovery failure loses its diagnostic evidence. No timeout experiment was executed.

Direction: export all created supervisor/worker/recovery streams and phase/outcome metadata before transient-root removal. If external evidence creation itself failed, retain or clearly report a durable alternate owned failure artifact rather than referring to a deleted file. Keep primary and cleanup errors distinct.

### HT4 — P2: performance failure-delta classifier misses failed label values

Location: `tools/powershell/Ferrum2.Performance/HostExecution.ps1:396`–`:412`.

Static fact: `Get-Ferrum2FailureCounterTotal` tests only the metric family name against `(drop|error|reject|failure|failed)`. Closed failures carried in labels are not inspected. For example `ferrum2_network_reset_total{reason="retry",result="failed"}` and `ferrum2_network_full_rebuild_total{...,result="failed"}` do not match the name expression, so their increases do not affect the asserted zero failure delta. Equivalent label-carried failures exist in rule-set/resolve families. The explicit family_disabled/invalid_destination exclusions are separate and are not the defect.

Impact: a PASS trial may still contain failed lifecycle transitions in its retained raw metrics; the reduction cannot justify an unqualified zero-failure statement. A workload success does not imply no intervening failed/retried reset. This is static classifier incompleteness; no particular historical run is asserted to contain the omitted failures.

Direction: use an explicit closed relevant metric schema (family plus label predicates), retain per-category deltas, and document intentional non-workload exclusions. Avoid solving this by counting every metric containing a word, which risks double-counting paired general/specific counters. Verify complete accepted/rejected schema rows in a pure parser contract.

## Startup evidence and port-allocation limits

`HostExecution.ps1` free-port helpers temporarily bind then close: metrics ports use OS ephemeral allocation, server TCP+UDP ports are selected in 20000..59999 and independently probed, support ports check one TCP plus four UDP numbers. They do not reserve ports through product binding. `HostProduct.ps1:17`–`:38` selects and records ports before config checks; client/TUN starts first, then server checks and starts at `:66` onward. This creates a real interval during which another process or a local ephemeral allocation could consume a chosen port. It does **not** identify the cause of Confirm 8d candidate trial 47 (`46/50`, server startup.bind). That incident remains unattributed.

The present product startup catch retains logs before cleanup, and later trial failure catches retain product metrics, workload logs and phase. These R5/R9/R10-style evidence improvements are present and were independently read. The product server's collapsed StartupBind category still cannot identify TCP/UDP/metrics or bind/listen stage; see composition C6. Design should first retain closed endpoint role/index/stage and owned-process exit status. Port retries, startup reordering or network-notification changes must follow actual evidence and must not silently discard failed trials.

## Authorization, ownership and recovery assessment

- Both public live entrypoints require explicit acknowledgement; mutation owners require an already elevated shell. Neither auto-elevates. Qualification's worker rechecks acknowledgement/elevation/source identity; its outer supervisor may create its temporary logs before the worker rejects elevation, but does not itself mutate network state.
- PlanOnly validates source closure and commit identity without starting product/network work. Static test scripts parse/inspect/import helpers and use PlanOnly or missing-ack behavior; their injected fixtures do not create a live TUN. Recovery inspects absent/completed protected ledgers unprivileged and requires elevation before pending removal.
- A shared global mutex excludes overlapping qualification/performance runs. The recovery root has an exact protected administrator-owned ACL with only Administrator/SYSTEM writes and Users read/execute. Run-root removal verifies RunId, canonical parent, plain directory and no reparse point. Ledger writes precede address/route creation and distinguish planned from created; recovery refuses ambiguous planned presence.
- Processes start suspended in a hidden new console, with only the three explicit standard handles inherited, join the kill-on-close job before ResumeThread, and record PID/executable/start time. Process recovery validates executable and creation time before killing a matching PID. The C# failure path terminates a newly created process, but does not await it; CloseGroup closes the kill-on-close job without querying active-process-zero and retains handle-table entries until individually closed. These are lifecycle hardening opportunities; no actual escaped descendant is shown.
- Planned adapter identity is persisted before startup. Failure between adapter creation and GUID readback intentionally refuses ambiguous recovery rather than deleting by name alone. This protects unrelated state but means the advertised recoverability has a deliberate fail-closed/manual-investigation window; tests/verdicts must not erase that limitation.
- Recovery validates resource identity before deletion, but a protected ledger is largely trusted for route/address scope and policy-store fields. The `policy_store` field is recorded but not used as a query restriction in removal. A later design should validate the closed ledger schema and RFC2544/exact-/32 ownership constraints before mutation, while retaining current refusal on identity mismatch. This is not a demonstrated unprivileged ledger-edit attack; the ACL is explicitly restrictive.
- Shared primitives are sizeable mixed owners: HostExecution includes generic execution and performance-trial/statistical extraction, while qualification imports that entire file. Qualification's source bundle therefore binds unused performance-specific code along with shared primitives. A cohesive extraction of true shared execution/identity helpers would improve consumer closure; avoid copying primitives or introducing another runner.
- The exported performance function also accepts a SafetyCheck mode not exposed by the canonical script. It is not a qualification verdict and is not called by qualification. Review whether this extra public module execution surface belongs in the intended single-runner interface.
- `$pid` naming in the shared launcher resembles an automatic-variable collision, but the coordinator has repeated successful live runs of the same module. Do not classify startup failure from this spelling. Prefer a descriptive non-system variable name during later edits; no system-variable assignment experiment was run.

## Qualification witness limits

The fixed eight checks, candidate build identity, source-bundle digest, WFP key/name/filter-ID/process readback, before/after probe success and forced job recovery all exist. WFP XML is kept transient; retained witnesses deliberately expose reviewed ownership identities rather than full host state.

The route-notification C# callback signals for any IPv4 route event and does not inspect the supplied row. The script adds an exact ledger-owned /32, waits for an event, waits a fixed second, compares WFP IDs and reruns probes. This demonstrates an OS notification was observed around the mutation and the WFP identity was retained; it does not correlate the callback to that exact row or prove the client completed a ResetNetwork. That narrower meaning may be correct for a semantically irrelevant route change. Do not force a reset or alter notifications merely to make a stronger claim.

On `CancelMibChangeNotify2` failure, QualificationRouteNotification.Dispose clears ownership, disposes the event and throws (`:78`–`:93`). Successful cancellation joins callbacks; failure does not establish unregister completion. Retaining the delegate/registration until closure is established deserves an explicit native-error policy. No native failure or invalid callback was reproduced.

The worker is killed after 840 seconds and timeout recovery gets 45 seconds; successful final verdict rejects elapsed >=900. Hashing/Add-Type/process creation and finalization occur outside the worker wait, so the 900-second wall-clock statement is not an independently enforced timer around every supervisor operation. Keep bounded-verdict validation distinct from a strict outer execution deadline.

## Native ordinary contract and producer/controller responsibility

`qualify_native.py` is a thin local/hosted selector. It checks OS/architecture/profile, exact release artifact paths, GitHub identity and clean checkout for hosted evidence; local mode refuses GITHUB_ACTIONS. `native_contract.py` uses numeric loopback configs, TCP/UDP loopback probes, bounded output capture, genuine process signals, rollback and rebind checks. No live TUN, route, DNS, WFP, physical adapter or privilege operation appears in the native contract. All four TOML fixtures are loopback-only synthetic-key inputs. Native artifact symlink checking happens after resolve, so it establishes the resolved executable identity rather than proving the caller-supplied path had no symlink component; do not claim a stronger path property.

Captured stdout/stderr have bounded retained bytes, but non-daemon reader threads may remain blocked if a descendant inherits a pipe; Windows kill paths terminate the root process rather than a job. Current Ferrum2 native binaries do not spawn such descendants in these scenarios. This is a bounded-harness robustness limitation, not a current TUN safety violation. Some socket/config setup happens before a cleanup try/finally in assert_routed_smoke; consolidate ownership during later maintainability work.

Performance runs one identical baseline-built M4 harness for baseline/candidate, after checking both exported source-bundle identities match. Producer emits raw checked work, measurements, checks and active-ready/complete markers. Controller samples product CPU around the active marker handshake, keeps percent and wall window, excludes support/harness CPU, and records lifetime peak working set (not an active-window peak). Quick/Confirm alternate AB/BA per pair and preserve all pairs; medians and MAD do not silently discard outliers.

The controller validates positive primary/I/O values, nonzero checked units and, when present, positive monotone p50<=p95<=p99 with latency_samples=min(checked_units,2,000,000). It preserves the producer's full measurements. It does not independently recompute percentiles from samples; the producer's sampling/quantile algorithm is outside this partition and must be reviewed by its owner. HT1 concerns the controller CPU reducer, not percentile generation. Lifecycle p95 is nearest-rank over 20 complete start/probe/stop durations.

`summary.status=PASS` means collection/reduction completed; each scenario has candidate-win/within-noise-band/regression. It is not proof that candidate won or that correctness qualification passed. Cleanup success remains required by the outer finally. Final product-source remediation and dedicated qualification must precede new CPU profiling; no historical profile is used here as evidence of current speed or a code-change benefit.
