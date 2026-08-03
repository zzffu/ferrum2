# CI 与验证状态

## M7 closed 状态

- **Qualified exact SHA:** `b3b99a15aa99f8393f99f4c72c85f451a48c6749`，tree
  `018a6ed1d6547771cd9921e51d2bc8668305b6b2`。Automatic push run
  [`30812399038/1`](https://github.com/zzffu/ferrum2/actions/runs/30812399038) binds every credited
  result to that SHA。
- **Local/review evidence:** format、Clippy、workspace binaries、all-features Full、ignored 100+
  lifecycle `1/1` in `129.42s`、docs、Rust 1.85、Windows focused、Linux focused and exact Linux
  executable stress `2000/2000` passed。M7-T08 Architect and QA both returned `PASS_WITH_NOTES`
  with no blocker、major or minor finding。
- **Hosted evidence:** quality `91681978507`、MSRV `91681978524`、Windows MSVC `91681978550`、
  Linux GNU `91681978495`、Linux musl `91681978557`、interop `91681978493` and Budget
  `91681978503` completed `success`。Exact markers record Full/security/process `PASS`、focused
  IPv6 UDP `PASS`、platform native/artifact/linkage `2/2` plus cleanup、and interop
  `tcp=12/12 tcp_cleanup=PASS udp=12/12 udp_cleanup=PASS`。
- **Budget truth:** T05 exact `9baba260` replaced the historical permanent-ratio failure with schema
  2。The exact local ticket/milestone and hosted CI gates all return `PASS` at code/tests/examples
  `15529/25482/132`，test growth `863/864`，remaining `1`；the hosted completion marker binds schema
  `2` to the exact SHA/run/attempt。
- **Boundary:** M7 is `closed` with zero blocking findings。Both authorized non-force pushes are
  consumed。Performance is excluded and is not awaited、credited or claimed；no rerun、further
  push、PR、tag、release or publication is authorized。The implemented budget analysis remains
  [`M7-test-budget-gate-analysis.md`](research/M7-test-budget-gate-analysis.md)。

## M6 closed 状态

- **Accepted exact-SHA qualification:** exact
  `7f1e45c174e749d3dddd32d187365722cce94dbe`, tree
  `fc2052de743ae5447617b59b06e331f468efd7a3`. Automatic push run
  [`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553) used
  that exact SHA for every credited job。
- **Local qualification:** serial format、Clippy、workspace binaries、Full、ignored
  100-cycle `1/1`、Rust 1.85、docs and diff checks passed。The final exact-ceiling budget
  returned `PASS_HOLD` in ticket、milestone and CI modes at code `15032`, tests `22853`,
  examples `132`, ratio `1.520290`; the accepted baseline remained unchanged。
- **Hosted qualification:** quality `91544432681`, MSRV `91544432690`, Windows MSVC
  `91544432726`, Linux musl `91544432739`, Linux GNU `91544432748` and interop
  `91544432703` completed `success` in the same run/attempt。The interop job's exact marker
  checks require TCP `12/12`, UDP `12/12` and both cleanup results before success。
- **Explicit M6 close boundary:** the user defined quality、MSRV、platform `3/3` and
  interop as sufficient hosted success。The existing long-running performance job and its
  dependent repository aggregate were not awaited, are not credited, and are not claimed as
  PASS。M6 adds no throughput/resource claim。
- **Authorization boundary:** the one authorized non-force push is consumed。No rerun、
  dispatch、second push、PR、tag、release or publication occurred or is authorized；this
  local documentation-only closeout is not hosted evidence。

## M5 closed 状态

- **Accepted exact-SHA qualification:** exact
  `6ca043460f0a5233a0b39c9931b4f3f3a22f1cba`, tree
  `3474c7896bb8e3042e323991616418c2a93c76b4`, product commit
  `db4f100c35a2fc6615828b9aa176e8ede62eb855`, baseline
  `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`. Automatic push run
  [`30743888837/1`](https://github.com/zzffu/ferrum2/actions/runs/30743888837)
  completed `success`; all eight jobs passed.
- **Local qualification:** serial Full passed; workspace all-features reported
  `261 passed / 0 failed / 2 expected ignored`, exact lifecycle `1/1` (libtest
  `127.49s`), Rust 1.85 and architecture/workspace policy `26/26` passed. The normal
  product graph contains only patched `shadowsocks-crypto 0.7.0` with exact `v2`;
  provenance, MIT license, unsafe/old-backend absence and protocol-source boundary
  checks passed.
- **Hosted qualification:** quality/security/process, MSRV, Windows MSVC, Linux GNU,
  Linux musl and final aggregation passed. Interop recorded TCP `12/12` and UDP
  `12/12`, both with cleanup. Performance recorded ferrum/reference medians
  `138726604/484138461`, ratio `0.286543242`, signed difference `-71.345675840%`,
  sessions `10000`, samples `180`, RSS windows `6/6`, drain and cleanup `PASS`.
- **Hosted jobs:** quality `91486022727`, MSRV `91486022717`, Windows MSVC
  `91486022736`, Linux GNU `91486022730`, Linux musl `91486022743`, interop
  `91486022695`, performance `91486022764` and qualification `91489792739` all
  completed `success` in the accepted run/attempt.
- **Budget/review:** milestone budget `PASS_HOLD`: code `14066`, tests `20985`,
  examples `132`, ratio `1.491895`, debt `107`; baseline unchanged. Final Architect
  and QA verdicts were `PASS`; `QA-T03-001` closed and no blocking finding remains.
  `QA-T03-N01` records the nonblocking anonymous raw-log download limitation.
- **Authorization boundary:** one authorized non-force push was consumed and revoked.
  No rerun, dispatch, second push, PR, tag, release or publication occurred or is
  authorized; this local docs-only closeout is not hosted evidence.

## M4 closed 状态

- **Accepted exact-SHA qualification:** exact
  `9b379a426853d86a184464f6fd8c73081b464535` automatic push run
  [`30730883667`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30730883667)
  completed `success`. Performance recorded ferrum2/reference medians
  `50860305/476470749` bytes/s, ratio `0.106743814`, signed difference
  `-89.325618602%`, selected THP apply/restore, exact 10k, `180/180`, `6/6`, drain,
  and cleanup. Final qualification passed performance, Full/security/process, MSRV,
  TCP/UDP `12/12` each with cleanup, all three platforms, and test budget.
- **Formal close review:** full review of exact local candidate `f14b2f9` returned
  Product `PASS_WITH_NOTES` (`M4-CLOSE-PROD-N01..N04`), Architect
  `PASS_WITH_NOTES` (`M4-CLOSE-ARCH-N001..N003`), and QA `BLOCK` on
  `M4C-QA-001..003`. This record-only repair closes the two documentation findings
  `M4C-QA-001/002`; `M4C-QA-003` is discharged only by verified post-commit removal
  of the clean integration worktree after its branch and commit are preserved.
  Final QA close verdict: `PASS`; `M4C-QA-001/002` were closed by the reviewed record delta, and `M4C-QA-003` was closed by verified removal of the clean integration worktree. No findings remain.
- **Narrow optimization and authorization:** `M4-TCP-NODELAY-001` is done at
  exact `c0de9bd`. The shared accepted-stream and post-connect product seams enable
  TCP_NODELAY for both client and server without a config or dependency change.
  Windows RED/GREEN, Quick, serial Full `6/6`, both budgets, and native-ext4 WSL
  focused/runtime tests passed. The first docs-only descendant also passed Full `6/6`.
  Scope `M4-REMOTE-TCP-NODELAY-A1` is consumed and revoked for one non-force push of
  this exact integration tree to `codex/integration/m4` and its automatic push run.
  The run succeeded; no retry, rerun, dispatch, PR, release, publication, or second
  push is authorized.
- **Final hosted attempt and authorization:** exact
  `35fb3f85633ee32ba5909ecbf5d74c4ad4a89f11` was pushed once under
  `M4-REMOTE-FINAL-A1`; that scope is consumed and revoked. Automatic run
  [`30725843401`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30725843401)
  passed performance, MSRV, interoperability, and all three native platforms. Quality
  alone failed before product startup on a pre-existing parallel UDP local E2E port
  race, and final qualification failed closed. No rerun, dispatch, PR, push, release,
  publication, or second push is authorized.
- **Performance evidence:** ferrum2/reference medians were `8580846/481626248`
  bytes/s, ratio `0.017816400`, and signed difference `-98.218359976%`. The selected
  THP profile applied and restored successfully; resource completed exact 10k,
  `180/180`, `6/6`, drain, and cleanup. Throughput has no minimum preview threshold.
- **Current local quality repair:** exact `5f4fed7` changes only `udp_local_e2e.rs` and
  reuses the existing file-level standard-library mutex pattern. Native-ext4 WSL
  reproduced the exact line-224 `occupy UDP` / `EADDRINUSE` failure on pre-fix
  iteration 4; after repair, default parallel and the minimized pair each passed
  `200/200`, the ignored IPv6 case and complete native-ext4 harness passed, Full passed
  `6/6`, and both budgets returned `PASS_ADVANCE`. WSL remains diagnostic only.
- **Local resource repair:** exact
  `56aadd4b25baacb6972ed9bf65ae5052a0d4c6a8` admits a complete identified initial
  exposition with no lazy active-flow sample as zero, while malformed or unidentified
  exposition still fails closed and post-load remains exact `10000`. Architect and QA
  independently returned `PASS` with no findings; release self-check reported
  `mutations=11`, Full passed `6/6`, and ticket/milestone budgets passed at code
  `13879`, tests `20740`, ratio `1.494344`.
- **WSL2 diagnosis:** exact five-second diagnostic candidate `e9dbe54` completed the
  hosted identity path `50/50` on a native WSL checkout. Mounted-worktree `git status`
  samples were `0.775`–`3.297` seconds; a controlled six-second delay returned the
  exact redacted class `checkout status probe timed out`. The final candidate uses a
  shared thirty-second limit only for identity/reference/hash probes and preserves the
  five-second I/O and reap limits.
- **Prior hosted result:** push run
  [`30697247986`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30697247986)
  completed `failure` on that exact SHA. Quality `91362102217`, MSRV
  `91362102198`, interop `91362102206`, Linux GNU `91362102192`, Linux musl
  `91362102207`, and Windows MSVC `91362102234` completed `success`.
  Performance `91362102185` failed, so final qualification `91362498191` failed.
- **Performance evidence:** hosted-profile preflight, pinned reference checks, and
  the locked workspace release build succeeded. The driver then exited after five
  seconds with `M4 qualification rejected: bounded identity probe failed`; the
  always-run process/evidence cleanup succeeded. No throughput trial, median, ratio,
  10k-idle sample, RSS window, or drain result may be credited.
- **Fresh hosted result:** push run
  [`30698815475`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30698815475)
  completed `failure` on exact `57d317d`. Quality `91366096428`, MSRV `91366096397`,
  interop `91366096415`, Linux GNU `91366096453`, Linux musl `91366096419`, and
  Windows MSVC `91366096439` succeeded; interop recorded TCP/UDP `12/12` with cleanup.
  Performance `91366096426` and final qualification `91366811029` failed.
- **Fresh performance evidence:** all hosted probes and ten throughput trials passed.
  Ferrum2 median was `7977915` bytes/s, reference median `478773248` bytes/s, ratio
  `0.016663243`. Resource then failed before load with `metrics readiness timed out`;
  cleanup succeeded. No resource sample, RSS window, or drain result may be credited.
- **Third hosted result:** push run
  [`30700273019`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30700273019)
  completed `failure` on exact `2f4190c`. Quality `91369961765`, MSRV `91369961748`,
  interop `91369961726`, Linux GNU `91369961746`, Linux musl `91369961738`, and
  Windows MSVC `91369961745` succeeded; interop recorded TCP/UDP `12/12` with both
  cleanup results PASS. Performance `91369961766` and qualification `91373764205`
  failed; the always-run performance cleanup succeeded.
- **Third-run performance evidence:** all probes, the release build, and ten throughput
  trials passed. Ferrum2 median was `9013384` bytes/s, reference median `480717482`
  bytes/s, ratio `0.018749857`. Resource passed readiness, established exact `10000`,
  and collected all 180 samples with stable active/fd/task tuples, then rejected RSS
  window 2 above 105%. Drain was not reached and no RSS window may be credited.
- **Third-run open-root diagnosis:** `HOSTED-M4-T02-001` and `HOSTED-M4-T02-002` are resolved.
  `HOSTED-M4-T02-003` is the RSS-window failure above. The runner-temp raw samples were
  correctly deleted, while the bounded error omits which binary and both first/current
  medians; this run therefore cannot distinguish measurement-induced allocation, an
  early baseline, actual idle growth, or runner RSS noise. Preserve the 105% gate and
  add only bounded redacted failure values before another hosted request. Exact
  `7b63bd5` implements that one-file repair; behavioral TDD, Architect/QA reviews,
  focused checks, and both budgets pass with no findings. The 105% gate and profile are
  unchanged. Local scope `M4-LOCAL-RSS-DIAG-001` is consumed and revoked; hosted
  observation is blocked pending a new exact single-use authorization.
- **Local WSL2 resource repair:** exact `d28ed0a` failed twice before sampling because
  the resource-only synthetic target inherited Rust's default listen backlog under
  fixed setup concurrency `256`; product active gauges reached `10000` while the target
  remained short and Linux reported listener overflows/drops. Exact `7c19e80` reuses
  pinned `socket2` to request backlog `10000` only for that target. Architect/QA both
  returned `PASS`; Full passed `6/6`, and both budgets passed at code `13906`, tests
  `20756`, ratio `1.492593`. A native ext4 WSL2 run exited `0` after `2131` seconds with
  target accepts `10000`, samples `180/180`, RSS windows `6/6`, exact drain, zero
  listen overflow/drop, and zero remaining processes. All six client/server
  median-twice values were `1909544/1966728` KiB. This is diagnostic only. Scope
  `M4-LOCAL-WSL-TARGET-BACKLOG-001` is consumed and revoked.
- **Fourth hosted result:** push run
  [`30704646072`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30704646072)
  completed `failure` on exact `4468f75`. Quality `91381542687`, MSRV
  `91381542662`, interop `91381542701`, Linux GNU `91381542683`, Linux musl
  `91381542715`, and Windows MSVC `91381542685` succeeded. Performance
  `91381542664` failed, so final qualification `91385637817` failed closed; both
  always-run cleanup steps succeeded.
- **Fourth-run performance evidence:** all probes, the release build, and ten throughput
  trials passed. Ferrum2 median was `9035229` bytes/s, reference median `547376332`
  bytes/s, signed difference `-98.349357020%`, and ratio `0.016506430`. Resource
  established exact `10000` and collected all 180 samples with stable active/fd/task
  tuples, then rejected RSS window 2: client median-twice remained
  `1907336/1907336` KiB while server moved from `2182832` to `2389976` KiB
  (`+103572` KiB actual RSS, `+9.4897%`). Drain was not reached.
- **Paired diagnostic source:** exact local source `1d3c117` keeps the formal `VmRSS` 105%
  gate unchanged and adds strict, bounded `smaps_rollup` parsing plus all-six paired
  trajectories. The first candidate was rejected because its parser fixtures lacked
  implementation-before RED evidence; the accepted rebuild records nine public-CLI
  RED/GREEN slices. Architect returned `PASS_WITH_NOTES`, QA returned `PASS`, Full
  passed `6/6`, and ticket/milestone budgets returned `PASS_ADVANCE` at code `14131`,
  tests `20756`, ratio `1.468827`. A native-ext4 WSL2 1 GiB probe measured 20 rollup
  reads at `12146` us average and `12992` us maximum versus the 10-second sample slot.
  The complete WSL2 profile exited `0` after `2103.6` seconds with exact 10k, `180/180`
  samples, `6/6` windows, drain, and zero remaining processes. All six client/server
  median-twice values were `1908928/1966960` KiB for both `VmRSS` and precise `Rss`,
  `1900872/1958128` KiB for `Anonymous`, and zero for `AnonHugePages`. This proves the
  instrument and local plateau only; it does not reproduce or satisfy the hosted gate.
  The 189-line, 73224-byte raw JSONL and the failed-start directory were deleted after
  the bounded summary; nothing was committed or uploaded. Scope
  `M4-LOCAL-RSS-PAIR-001` is consumed and revoked. At that checkpoint M4-T02 was
  blocked pending the subsequently consumed exact remote authorization.
- **Paired hosted result:** push run
  [`30710439015`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30710439015)
  completed `failure` on exact `a53a5d7`. Quality `91396837397`, MSRV
  `91396837448`, interop `91396837406`, Linux GNU `91396837379`, Linux musl
  `91396837383`, and Windows MSVC `91396837385` succeeded. Performance
  `91396837357` failed, final qualification `91400971821` failed closed, and the
  always-run performance cleanup succeeded.
- **Paired performance evidence:** throughput passed with ferrum2 median `9651268`
  bytes/s, reference median `476676096` bytes/s, ratio `0.020247015`, and signed
  difference `-97.975298514%`. Resource
  established exact `10000`, retained stable active/fd/task tuples for all `180`
  samples, then failed the unchanged 105% gate at window 2. Client `VmRSS`/precise
  `Rss` median-twice trajectories were
  `[1907184,1907184,2042444,2254648,2444520,2444520]`; server trajectories were
  `[2217840,2435656,2511632,2511632,2511632,2511632]`. Every paired `VmRSS` and
  `Rss` value is equal. RSS minus `Anonymous` remains constant for each binary, while
  final client/server `AnonHugePages` reach `2387968/2437120` median-twice KiB.
  Both binaries plateau. The observation is consistent with delayed THP backing, not
  a `/proc/status` accounting-only false positive; stable ownership and the plateau
  contradict owner-count growth but do not establish the hosted allocator/kernel
  causal path. Drain was not reached because the gate failed.
- **Mechanism check and historical authorization boundary:** WSL2 reports THP `madvise`. A
  temporary 256 MiB anonymous mapping, sparsely touched before `MADV_HUGEPAGE`, moved
  from `Rss/Anonymous/AnonHugePages=10888/4576/0` KiB to
  `109136/102696/98304` KiB over 60 seconds in 16 MiB steps without changing the
  mapping, demonstrating one compatible delayed THP-residency mechanism but not the
  hosted product run. Historical scope `M4-REMOTE-a53a5d7-A1` is consumed and revoked;
  the current repair and authorization are recorded above.

## 当前 M3 closed 状态

- **Qualified product SHA:** exact
  `d9e59d787c3fe78dfca778ee8a36668a45387368` remains on remote
  `origin/codex/integration/m3` and contains M3-T01～T03、T06、T05、T07、
  T08。Local `master` and `codex/integration/m3` entered close mode at
  docs-only descendant `d784b06171723bb93fd467cea1a799f58f7d60b0`；
  `d9e59d78...` is its direct product parent, not the current local tip。
  M3-T04 remains explicitly `deferred` after its terminal targeted escalation;
  T06 carries the approved replacement outcome.
- **Durable workflow state:** M3-T01～T03、T05～T08 are `done`; T04 is
  `deferred`; active runtime phases and open canonical blockers are empty.
  The helper's pre-close terminal action remains `ready_to_close` because it
  has no separate milestone-close mutation；roadmap、verified context audit
  and handoff now record durable `closed`。
- **T05 convergence:** initial `441b2903...` received Architect full `PASS`
  and QA full `BLOCK` under major `QA-M3-T05-001`; the sole repair
  `bba40d12...` received same-reviewer targeted `PASS`. Native qualification
  contract, focused platform evidence, quick `5/5`, full `6/6`, ticket
  budget, diff, ownership, control-plane, review and integration gates passed.
- **T07 convergence:** exact `bc14971c...` removed only the non-isolated
  process-global child baseline from the portable UDP row. The complete
  four-thread binary passed `100/100`; fresh Architect/QA full reviews both
  returned `PASS`; quick `5/5`, full `6/6`, budget/control/diff gates passed.
- **T08 convergence:** exact `d9e59d78...` changed only the named
  server-private terminal-UDP test, substituting the existing bounded target
  datagram for the fixed 100-yield readiness guess. The exact test, affected
  two-thread UDP subset `100/100`, server suite `16/16`, fresh full
  Architect/QA `PASS`, quick `5/5`, full `6/6`, budget/control/diff gates all
  passed. No production behavior changed.
- **Final local budget:** milestone gate against M2 base
  `7907cda05a56e1c3b85af2dd8faeb85a385154b7` passed at code `12956`,
  tests `19861`, ratio `1.533`, delta code/tests `1242/627`, allowance `1362`.
- **Final hosted qualification:** exact one-use scope
  `AUTH-M3-T08-REMOTE-001` was consumed and auto-revoked `1/1` immediately
  before one non-force fast-forward push of `d9e59d78...` to
  `refs/heads/codex/integration/m3`. GitHub Actions
  [run `30494736004`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30494736004),
  event `push`, completed `success`.
- **Same-run jobs:** quality `90720794923`, MSRV `90720794873`, Windows MSVC
  `90720794992`, Linux GNU `90720795107`, Linux musl `90720794921`, interop
  `90720794966`, and final qualification `90721365575` all completed
  `success` on the same exact SHA/run/attempt.
- **Failure history and roots:** failed runs `30472227257/1` at `bba40d12...`
  and `30476271774/1` at `bc14971c...` remain immutable and are not spliced.
  The latter proved the repaired portable row in both quality and MSRV before
  exposing the distinct server-private readiness defect. Fresh run
  `30494736004/1` resolves `HOSTED-M3-T07-002`; earlier
  `HOSTED-M3-T05-001` was already resolved. No open root remains.
- **Close reviews:** Product Manager `PASS_WITH_NOTES`、Architect
  `PASS_WITH_NOTES`、QA `PASS` on local `d784b061...` plus hosted-qualified
  product `d9e59d78...`/run `30494736004/1`。No blocker/major remains；
  Architect note `ARCH-M3-CLOSE-N01` was a one-character T06 evidence SHA
  transcription and was mechanically corrected during closeout。
- **Close validation source:** execute's final authoritative full gate on exact
  `d784b061...` passed `6/6` immediately before close；milestone budget against
  M2 base passed at `12956/19861/1.533` versus baseline `1.642` and required
  `1.592`。The closeout working tree also passed authoritative full `6/6`；
  seven-entry context inventory/strict check、workflow validation、
  control-plane check、budget baseline write and handoff validation passed。
- **Authorization/publication:** all eight M3 local and remote grants were
  exact, single-use, consumed, and revoked. No rerun, dispatch, remote
  `master` update, force-push, PR, tag, release, archive, upload, signing,
  publication, ref deletion, or control-plane mutation occurred. Close mode
  performs no remote mutation and creates no new authorization.

## 当前 M2 closed 状态

- **Qualified M2 close candidate:** exact
  `7907cda05a56e1c3b85af2dd8faeb85a385154b7` on
  `codex/integration/m2` combines the previously qualified T05
  product/control lineage, reviewed root-cycle control commits
  `dd646ae861a105ee104425fdb327100209fe1b3c` /
  `9528679a89853fe7df62b368c6b84c585c811071`, and reviewed T06 evidence
  candidate `d1c12627632112826fe3dee884caf5facb291e48`. The seven changed paths
  are tree-equivalent to their exact reviewed component candidates.
- **Exact local close gates:** authoritative quick `3/3`, full `4/4`,
  workflow control `75/75`, qualification contract `13/13`, workspace policy
  `17/17`, and UDP local `3 passed / 1 ignored` all passed. The ignored
  focused IPv6 row was not credited on Windows. Ticket budget passed at
  delta code/tests `0/120`, allowance `120`; milestone budget passed at
  code/tests `3994/3475`, allowance `4114`, with total
  `11714/19234` and ratio `1.642`.
- **Final authorized M2 close qualification:** single-use scope
  `m2-20260729-remote-qualification-7907cda-a1` was consumed `1/1` before
  fast-forwarding only exact `7907cda` to `origin/codex/integration/m2`, then
  auto-revoked. GitHub Actions
  [run `30425476328` attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30425476328),
  event `push`, completed `success`; all six expected jobs succeeded:
  `quality` (`90490943645`), `msrv` (`90490943661`),
  `platform / linux-musl` (`90490943702`),
  `platform / linux-gnu` (`90490943716`),
  `platform / windows-msvc` (`90490943726`), and
  `interop` (`90490943768`).
- **Focused IPv6 raw-log evidence:** quality selected
  `ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps`
  exactly once and reported `ok`, `1 passed`, `0 failed`, `0 ignored`.
  `m2_ipv6_udp_real_process` appeared once with `datagrams=3` and
  payload/source/cleanup all `PASS`; its completion marker appeared once and
  bound exact SHA `7907cda`, run `30425476328`, attempt `1`.
- **Interop raw-log evidence:** provider setup reported
  `sing_box=0 shadowsocks_rust=0`; all twelve TCP case IDs and all twelve UDP
  case IDs reported `PASS`; both transport summaries reported `12/12` and
  `cleanup=PASS` on the same SHA/run/attempt; final status reported provider,
  qualification, and cleanup values all zero.
- **Close state:** `M2-CLOSE-IPV6-001` and the review-control root are
  resolved, M2-T01～T06 are `done`, active runtime phases and open roots are
  empty, and the pre-close scheduler returned `ready_to_close`. Product and
  Architect close reviews returned `PASS_WITH_NOTES`; QA returned `PASS`.
  Remaining notes are nonblocking `M2-INT-QA-001` and
  `ARCH-M2-T05-HOSTED-N02`. The later local closeout-document commit is not
  a separately hosted-qualified product SHA.

- **Wave-3 T04 product integration:** exact
  `980540bd439c438eb196cbc3096cbea0cda3fb4d`; contains initial T04
  candidate `aac21f48b6bd3cb3aa940a60628e5b94eaac89d6`, lifecycle repair
  `6896c6e026797cd62fd9787a66abcca6ec6c7b58`, and mechanical
  integration-evidence repair `c6ade6d34ee95767852cfa25327a4fb6da520a46`.
- **Wave-3 reviews:** full Architect/QA `BLOCK` findings
  `ARCH-M2-T04-001` and `QA-M2-T04-001` were resolved by the one
  substantive repair; both targeted reviews returned `PASS_WITH_NOTES`.
  `M2-T04-INTEGRATION-001` was resolved by isolating legacy TCP-only
  fixtures from default-enabled UDP without weakening config/dual-bind
  evidence. Exact-SHA Architect/QA integration reviews both
  `PASS_WITH_NOTES`; `QA-M2-T02-N01` is satisfied.
- **Wave-3 local gates:** exact binary build, authoritative quick `3/3`,
  full `4/4`, focused/workspace all-features 100-cycle lifecycle,
  workflow validation/review/integration checks, and diff checks all exit
  `0`. Ticket budget `PASS`: code `11582`, tests `18721`, ratio `1.616`,
  baseline `2.041`; delta `954/774`, allowance `1074`.
- **Wave-4 T05 product integration:** exact
  `90c173f014f84761ee485ec584b7aa3fe8e7abab`; cherry-picked initial
  `6c321ebbed07e426e66b8257792920595cfc0dd2`, first repair
  `975276a90b6ae4b5a9bd984bcc31e3709d473ed5`, and user-authorized
  superseding repair `bc589ee53e3fbf093bfe876e40a962e9f43444c2` as
  `0801a39095fd1c088698c3a2bf75062fc0bc8061`,
  `0f3c8ae8d42df9d4333ed9bc04570a5e28531a44`, and
  `90c173f014f84761ee485ec584b7aa3fe8e7abab`.
- **Wave-4 reviews/control:** full and targeted Architect/QA history,
  including both targeted `ESCALATE` verdicts, remains preserved.
  User-authorized `bc589ee` resolves the ADR-0014 ordering and mandatory
  budget IDs; both superseding reviews returned `PASS` and
  `M2-T05-REVIEW-001` is resolved. The narrow workflow-control amendment
  `dff012a4a7ec88b0d5492b2efe9bea76c4510f30` passed focused `3/3`,
  full workflow `67/67`, and exact-SHA Architect/QA control reviews.
  Final integration Architect returned `PASS`; QA returned
  `PASS_WITH_NOTES` with nonblocking `M2-INT-QA-001`.
- **Wave-4 local gates:** workspace binaries, protocol example, and
  Cargo-managed qualification entry build; pure qualification contract
  `12/12`; authoritative quick `3/3`; full `4/4`, including strict
  Clippy, all-features tests, fixed 100-cycle lifecycle, and docs;
  metadata, workflow validation, review/integration gates, and diff/status
  checks all pass. Ticket budget passes at code `11714`, tests `18971`,
  ratio `1.620`, delta `1086/1024`, allowance `1206`; milestone budget
  passes at `3994/3212`, allowance `4114`.
- **First M2 hosted run:** authorized push-triggered run `30408245840`,
  attempt `1`, on exact `a168b89eb8dcd0c7a06df06b95a57d63893f2ab6`
  passed quality, MSRV, Windows, Linux GNU/musl, and both provider setup
  steps. UDP passed `12/12`; TCP passed `9/12`. SingBox reference-client
  rows `M1-INT-003/007/011` failed because `ApplicationCleanEof` was
  recorded before target EOF/shutdown evidence, so combined cleanup
  remained failed. The run is preserved as failed evidence and was not
  rerun or spliced.
- **Hosted-ordering local repair:** exact product candidate
  `0395d7dfb170ddc8c3328b2d939210d96c81266f` restores the bounded
  target-shutdown/application-acknowledgement causal edge. Repair-base
  budget passes at `0/120` with allowance `120`; original ticket-base
  passes at `1086/1144` with allowance `1206`; qualification contract is
  `13/13`. QA exact-SHA verification returned `PASS`; Architect returned
  `PASS_WITH_NOTES`, retaining only the 100 ms scheduler-bound advisory.
  Append-only review control `f95b821f` plus sole repair `6bc85d65`
  passed focused `5/5`, full workflow `73/73`, targeted Architect `PASS`,
  and QA `PASS`. Preliminary local product/control integration is
  `6a4e35062bd6d1631a029230e7cffdc3ba0f7db6`.
- **Final local gate reliability repair:** pre-repair assembly `6fd07a0`
  first ran two full gates concurrently; one passed and the other timed
  out while observing the production lifecycle registry. The exact failed
  lifecycle row then passed once and `20/20` in isolation. A later
  serialized full exposed a separate Windows fixture defect:
  `config_cli` selected a TCP dynamic port inside a UDP exclusion range
  and failed with `WSAEACCES` before starting the product. A bounded
  TCP-port-to-UDP-bind probe reproduced `100/200` failures on excluded
  ports `59999..60098`. Root `M2-T04-PORT-001` was resolved by mechanical
  repair `87c3c32c508222595cd78f442ce6091b5818e1ec`, integrated as
  `3fae42ab10d5ef97c0e8924a53d5f6c6b9281569`: the occupied-port fixture
  now retains a compatible TCP+UDP pair, retries only expected
  `PermissionDenied`/`AddrInUse` failures within 256 attempts, and keeps
  every original assertion. Focused repetition passed `256/256`, repair
  budget passed at `0/23` with allowance `120`, and the serialized exact
  integration full gate passed `4/4`. The initial `record-repair` command
  was rejected because no active repair phase had been set; no force or
  ledger rewrite was used. The canonical root resolution contains the
  exact repair and validation evidence, and workflow validation passes.
  No remote action occurred.
- **T05 authorized hosted qualification checkpoint:** reviewed assembly
  `52d1610a127349e7a817a67c81c77e0383d20d1e` was fast-forward pushed only
  to `origin/codex/integration/m2` under single-use scope
  `m2-20260729-remote-qualification-52d1610-a1`. GitHub Actions run
  `30415717152`, attempt `1`, event `push`, completed `success`; all six
  expected jobs succeeded: `quality`, `msrv`, `platform / windows-msvc`,
  `platform / linux-gnu`, `platform / linux-musl`, and `interop`.
  Interop raw logs record `provider_setup sing_box=0 shadowsocks_rust=0`,
  TCP `12/12` with `cleanup=PASS`, and UDP `12/12` with `cleanup=PASS`;
  both summaries bind exact SHA `52d1610a`, run `30415717152`, attempt `1`,
  and final status is
  `sing_box=0 shadowsocks_rust=0 qualification=0 cleanup=0`.
  The authorization was consumed `1/1` before push and auto-revoked. No
  force-push, rerun, `workflow_dispatch`, `master` push, PR, tag, release,
  publication, ref deletion, or other remote mutation occurred.
- **Wave-2 product integration:** exact
  `6e54cce52e5e29135acd91f6337a4516a094852e`; contains initial M2-T02
  candidate `0d88666d2f46ef85b376c12c55ffb34a784a8451`, repaired candidate
  `4d1c65b4d9af03f008b51cae3b5f058ca1edea64`, and coordination-only
  review-note commit `d268f46435830bdf4f392618071b90ce4b7cee1f`.
- **Wave-2 reviews:** QA full `PASS_WITH_NOTES`; Architect full `BLOCK` on
  `ARCH-M2-T02-001`, followed by the one substantive repair and targeted
  `PASS`. Exact-SHA Architect/QA integration gates both `PASS_WITH_NOTES`.
  The root is resolved; accepted debt `QA-M2-T02-N01` requires T04 to place
  request and response protocol commits inside T03 reserved closures.
- **Wave-2 local gates:** workspace binary build, authoritative quick 3/3,
  authoritative full 4/4, workflow validation/review-state/integration-gate
  checks, and `git diff --check` all exit 0. Ticket budget `PASS`: code
  `10628`, tests `17947`, ratio `1.689`, baseline `2.041`; delta
  `918/1010`, allowance `1038`.
- **Wave-1 product integration:** exact
  `0dff5c104149e7042f5e62dc10831f208a0e16ad` on
  `codex/integration/m2`; contains repaired M2-T01 candidate
  `c7ebe918e2d02664ec21fcfad85c301cbb6d3c01` and repaired M2-T03
  candidate `491954d8ea8fdf5faad17b0b360f353283d44898`.
- **Reviews:** T01 QA full `PASS`; Architect full `BLOCK` on
  `ARCH-M2-T01-001`, followed by one substantive repair and targeted `PASS`.
  T03 Architect/QA full `BLOCK` on `ARCH-M2-T03-001` and
  `QA-M2-T03-001`; one combined repair received both targeted `PASS`
  verdicts. Wave-1 exact-SHA Architect and QA integration gates both `PASS`;
  no blocker/major finding or accepted review debt remains.
- **Local gates:** workspace binary build, authoritative quick 3/3 and full
  4/4, workflow validation/review-state/integration-gate checks, and
  `git diff --check` all exit 0. An initial full run lost an exact lifecycle
  rebind race to the user's existing `sing-box.exe`; the focused harness
  passed 5/5 and the unchanged-candidate full retry passed. This is recorded
  as environmental evidence, not a product waiver.
- **Test budget:** combined ticket gate `PASS`: code `9710`, tests `16937`,
  ratio `1.744`, baseline `2.041`; delta `1990/1178`, allowance `2110`.
- **Remote/release history:** the failed superseded
  `a168b89` / `30408245840` attempt `1` remains unchanged historical
  evidence. T05 qualification was first credited at
  `52d1610a` / `30415717152` attempt `1`; definitive M2 close evidence is
  credited only from `7907cda` / `30425476328` attempt `1`. No run is
  spliced. The release gate is clear, all six tickets are done, no open root
  or active phase remains, and M2 is closed. No second push, rerun,
  `workflow_dispatch`, remote `master` update, PR, tag, release, publication,
  ref deletion, or other remote mutation occurred.

## 当前 M1 closeout 状态

- **Current product/control integration checkpoint:**
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef` on
  `codex/integration/m1`；包含 product checkpoint
  `fba23ca0b628bd6935d0977e3d9df7836b957e78`、reviewed M1-T01 candidate
  `4223051eeae35220b150461cad91daf09a954423` 与 M1-T02 candidate
  `ae84631c515933f60b2aa3f898a86fa3cff11ce9`，以及 M1-T03 candidate
  `4c9ad421e0ef5d193e29e70ed5a674cb30a4aa88`、M1-T04 candidate
  `b7a69899e4053e78fe8824e2cd9215b9d232e106`。本地 workflow-control
  commits `91bb86b`/`3bdde10` 支持并审计一次性 superseding review；
  `81345fbb56ac4cdbf1aea3a3f020d6fd514b187f` 恢复 ticket/milestone
  test-budget gate 的既有分层语义；`02c7bc7` 是其 integration commit，
  `874c83d` 增加 execute close-gate evidence。closeout source
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 只增加 hosted evidence
  文档，不是新的 product/release SHA。
- **Date/environment:** 2026-07-28（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1；Python 3.11.9。
- **Reviews:** T01 Architect full `PASS`、QA full `PASS_WITH_NOTES`
  （advisory `QA-M1-T01-001`）。T02 初始 Architect/QA full `BLOCK`
  （`ARCH-M1-T02-001`/`QA-M1-T02-001`）；first repair 后 QA targeted
  `PASS`、Architect targeted `ESCALATE`；one-use user-authorized additional
  repair `ae84631c` 后 Architect superseding `PASS`。canonical root
  `M1-T02-REVIEW-001` 已关闭，历史记录未覆盖。T03 Architect/QA full 均
  `PASS_WITH_NOTES`，无 blocker/major/repair；notes 为
  `ARCH-M1-T03-001`、`QA-M1-T03-001/002`。T04 Architect/QA full 均
  `PASS`，无 finding/repair。M1 closeout 的 Product Manager、Architect 和 QA
  均 `PASS_WITH_NOTES`；没有新 blocker/major finding。`QA-M1-CLOSE-A01`
  是由本次 roadmap、CI、handoff 和 baseline commit 完成的程序性 close 动作，
  不是 candidate defect。
- **Ticket/quick evidence:** T01～T04 ticket commands 均 exit 0。T03 Team Lead
  admission 的 config/client/server 31 tests 与五个 harness targets 17 tests
  均 PASS；T04 qualification entry 只 build，pure contract 10/10 PASS，未执行
  external entry。最终 integration binary build、fmt、workspace all-target check
  与 workspace tests 均 exit 0。
  clean integration target 首次 quick 的 workspace tests 因 process binaries
  尚未 build 而 exit 101；`cargo build --workspace --bins --locked` exit 0 后，
  同一未修改 SHA quick 3/3 exit 0。该 setup-order derivative 已记录为 review
  debt，不是 product blocker。
- **Full evidence:** close mode 在 final exact integration `874c83d` 重跑
  workspace binary build 与 authoritative full：
  `cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、
  `cargo test --workspace --all-features --locked`、
  `cargo doc --workspace --all-features --no-deps --locked`，4/4 exit 0；
  `git diff --check` exit 0。首次 test wrapper 在 60 秒到达工具执行上限而 exit
  124，没有产生 test verdict；同一未修改 SHA 的捕获式重跑在 92.6 秒 exit 0，
  所以该项是 environment/setup derivative，不是 product failure。
- **Test budget:** T04 ticket gate PASS：code `7386`、tests `15216`、ratio
  `2.060`；delta `+0/+120`，allowance `120`。M1 milestone gate 在
  `874c83d` PASS：code `7720`、tests `15759`、ratio `2.041321`；pre-close
  baseline `7031/14707/2.091737`；required ratchet ratio `2.041737`；
  planning-base delta `+689/+1052` 只报告、不复用 ticket allowance。三方 close
  review 接受 candidate 后，`codex/test-budget-baseline.json` 已以
  `master@dd17233e292262c80bfd8f0e5a0db4bc0361244e` 为来源更新为
  `7720/15759/2.041321`。
- **Workflow control evidence:** 66 unit tests、`workflow.py validate`、
  `py_compile`、`git diff --check` 均 exit 0；两项 control hardening findings
  `CTRL-M1-T02-001/002` 在 integration 前关闭。close gate 首次真实 FAIL
  定位为 ticket allowance 被错误复用于 milestone；最小脚本修复及 focused
  pass/fail ratchet regression 已在独立 control worktree 提交并由 Team Lead
  复核，无新授权、豁免或产品改动。closeout docs/baseline working tree 再次
  运行同一 workflow unit suite 66/66 PASS，`workflow.py validate` 与
  post-ratchet `test-budget --gate report` 均 exit 0。
- **Authorization:** three exact single-use local scopes for the T02 additional
  repair, control amendment, and superseding Architect review were consumed and
  revoked。用户随后授权 exact remote qualification；scope
  `m1-20260728-remote-qualification-874c83d-a1` 在 push 前原子消费并因
  `max_uses=1` 自动撤销。没有 force-push、rerun、ref deletion、PR、tag、
  release、publish 或 remote `master` 授权。
- **Scheduler/blockers:** M1-T01～M1-T04 done；当前无 active ticket、release
  dependency 或 open canonical root。pre-close helper action 为
  `ready_to_close`；roadmap durable status 现为 `closed`。close mode 没有
  implementation wave、product repair 或新 authorization。
- **Local qualification notes:** 本 Windows host `[::1]` bind 成功但 raw connect
  返回 `WSAEACCES`，所以 T03 real-process IPv6 row 是 **NOT EXECUTED**；IPv4
  fallback 只证明第三方法 echo/half-close。local platform artifact run 另因
  fixed port 1080 被占而 setup-blocked，不计本机 PASS。同一 exact-SHA hosted
  platform matrix 已补齐 Windows MSVC、Linux GNU、Linux musl success；历史
  IPv6 review note 保留，不把本机 fallback 改写为 IPv6 PASS。close 时对
  authenticated `quality` raw log 的 exact marker audit 证明
  `success_bounded_method_matrix_preserves_bytes_and_half_close` 恰出现一次，
  `SKIP real-process IPv6 row: host IPv6 loopback connect unavailable` 出现零次。
- **Hosted qualification:** exact
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef` 已仅 push 到
  `origin/codex/integration/m1`。GitHub Actions
  [run `30367147537`, attempt 1](https://github.com/zzffu/ferrum2/actions/runs/30367147537)
  为 push event 且整体 **success**；同一 run/attempt/SHA 的 `quality`、`msrv`、
  `platform / windows-msvc`、`platform / linux-gnu`、
  `platform / linux-musl`、`interop` 六项全部 success。interop 的 pinned
  reference provisioning 与 hosted qualification steps success；登录态 raw
  step log 精确包含 `M1-INT-001`～`M1-INT-012` 各一条 `status=PASS`，无
  FAIL/missing/duplicate。没有跨 run 拼接、rerun 或 publication。

## 当前 M0 closeout 状态

- **Current product integration checkpoint:**
  `8318ef106d6cd4e029bd3b02aa64125fabdda462` on
  `codex/integration/m0`; it contains reviewed material for M0-T01～T10.
  Local `master` was fast-forwarded to it, and the current evidence checkpoint
  records all ten durable ticket states as done.
- **Date/environment:** 2026-07-28（Asia/Shanghai）；Windows x86_64；
  Rust/Cargo 1.97.1
- **Latest hosted run:** exact `8318ef106d6cd4e029bd3b02aa64125fabdda462`
  GitHub Actions run `30331336772`, attempt 1, push event，整体
  **success**。同一run/attempt的quality、MSRV、Windows MSVC、Linux GNU、
  Linux musl和interop六项required results全部success；没有跨run拼接。
- **Current implementation frontier:** none；M0-T01～T10均已done。Cargo-managed
  qualification由本机compile/lint与pure-state tests覆盖但不执行external entry；
  hosted profile已收敛为quality、MSRV、三平台matrix及一个四案interop，共四个
  definitions/六个rendered results；11-job self-audit、filter/count、
  linker-help和重复Ubuntu jobs已删除。
- **Current blocker ledger:** M0没有open canonical root。
  `M0-CI-CONVERGENCE`及其`M0-T10-MSRV-FRESH-BINARIES` derivative已由
  exact-SHA local/review gates和run `30331336772`关闭。
- **Authorization:** 一次性scope
  `m0-20260728-final-integration-push-8318ef1`已在正常push前原子消费并耗尽。
  当前没有第二次push、rerun、PR、branch-protection、tag或release授权。
- **Closeout verification:** 2026-07-28 Team Lead在clean
  `codex/integration/m0@8318ef106d6cd4e029bd3b02aa64125fabdda462`
  重新执行authoritative full：`cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、
  `cargo test --workspace --all-features --locked`和
  `cargo doc --workspace --all-features --no-deps --locked`，四条均exit 0。
  GitHub public run page与jobs API只读复核同一SHA/attempt的六项job均为
  `completed/success`；匿名job-log不可见不改变已reviewed fail-closed workflow
  与provider结论的边界。

## 历史修复状态（保留记录）

- **First authorized hosted run:** exact `51fb7327` was pushed only to
  `origin/codex/integration/m0`; GitHub Actions run `30301746374`, attempt 1,
  instantiated all eleven jobs and completed **2 success / 9 failure**. Both
  interop jobs succeeded. The run remains failed historical evidence.
- **Independent hosted-like RED:** Arch WSL current build exit 0；lifecycle
  full-file and full-name exact rerun each exit 101 at the first client-proxy
  exact rebind (`EADDRINUSE`), with no remaining listener and the address in
  `TIME_WAIT`. Independent socket semantics probe exit 0 proved default
  TIME_WAIT rebind fails, old/new Unix reuse succeeds, and a live same-policy
  contender still fails. Broad config `valid` and replay `exact` list commands
  each exited 0 with count 2. WSL MSRV was not run after setup-only `ENOSPC`
  exit 101 and install timeout exit 124；all dedicated temp/process state was
  cleaned.
- **Exact `51fb7327` local gate evidence (Team Lead and independent QA; every
  listed command exit 0):**
  `cargo fmt --all -- --check`；
  `cargo check --workspace --all-targets --locked`；
  `cargo test --workspace --locked`；
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`；
  `cargo test --workspace --all-features --locked`；
  `cargo doc --workspace --all-features --no-deps --locked`；
  `cargo +1.85.0 check --workspace --all-targets --locked`；
  `cargo +1.85.0 test --workspace --locked`；
  `cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked`；
  `cargo test -p ferrum2-m0-harness --test scope_audit --locked`。四个
  `external_interop --ignored --exact <case>` commands各exit 0；local Windows
  release/config/detection evidence也exit 0。最终worktree clean、`target/` absent、
  owned child count 0。
- **M0-T01:** original integration Architect/QA **PASS**；现依用户授权为
  ADR-0009 的一次独占 manifest repair reopen；document Product/Architect
  **PASS_WITH_ACTIONS** 的 required corrections 已完成，QA final **PASS**；
  repair candidate `edaee3d73c5b5e2d7db7bf86a4165565336d8a0a` 已完成
  4-path implementation；Architect/QA ticket gates **PASS**，core 4/4、
  architecture 6/6、workspace-policy 13/13 与全部 ticket commands exit 0；
  lock identities 110→110、0 differences；integration
  `4f3f0ac098fb8f4df054bb52b8ba9f2f93f3cd63` 同组 gates **PASS**，done
- **M0-T05:** `d03e0065efd13ff215cc55be6257c305e8e69175`；
  ticket Architect/QA **PASS**；integrated
- **M0-T06:** `50f547f380d6c58d5538b6540fdc43cb29b5c89c` +
  repair 1/2 `721ed023703601d67dc2cfaad36d31502418373a`；initial
  Architect **BLOCK** / QA **FAIL**，repair re-review 与 final integration
  Architect/QA 均 **PASS**
- **Wave-2 integration:** `999d4f95a2d597fb283689b9306d2a6773af707d`；
  17 个新增路径均属于 T05/T06，final Architect/QA **PASS**
- **M0-T02:** **DONE**；ADR-0004 固定的
  `gcmtestvectors.zip@f9fc479e...a023` 不含批准的 numeric cases。实际来源为
  McGrew/Viega GCM proposal TV archive
  `511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0`
  的 `vec-01.txt`/`vec-02.txt`；ADR-0008 窄勘误已获显式授权，数值向量与
  密码/协议行为不变；contract Architect **PASS**、QA **PASS**。实现
  `45c0e2f` + repair 1/2 `df22d7e` 的 provenance/nonce repair 已 PASS；
  prior overall gate 只因 resolved graph 未启用 `aes/zeroize`/`ghash/zeroize`
  而 BLOCK。ADR-0009/T01 blocker 已由 `edaee3d`/`4f3f0ac` 关闭；combined
  integration `f9e218eca241f3002500b932fdcb4db93c52313b` Architect/QA
  **PASS**，T02 3+2+6、policy 13、architecture 6、core 4 与
  SOCKS5/runtime 36，合计 70 tests PASS；lock identities 110→110、0 differences。
  该历史checkpoint不足以单独证明真实`TcpSealer`/`TcpOpener` private nonce
  owner exhaustion；narrow candidate `6a058035`与integration `bb5c47ec`新增
  exact 2/2 crate-private real-owner tests，全部T02 commands和ticket/integration
  Architect/QA均PASS，worktree clean。T02恢复done；T03 common-SHA mapping仍待执行
- **Current frontier:** 原M0-T03最终integration
  `4bf758ae76421856bb527db3afe165d47e6fd4aa`已通过15项ticket commands、
  T02 exact 2/2、T03 exact 4/4、Architect/QA gates并done。T07 coordination
  checkpoint `ad9e499`之后，Engineer在保留worktree生成clean partial commit
  `52dcdb00a82ed0ab07601f86a985de853c1df00f`：binary build、config CLI 3、
  CLI contract 3、local E2E 4、client endpoint 1、client adapter 5、server
  adapter 6、workspace fmt/check/test与strict Clippy均exit 0；没有manifest/lock/
  lifecycle/native-probe/control-doc change，也未integrate。composition preflight
  发现四个合同证据缺口：黑盒counter visibility、stale fixture native branch、
  fused client connect/first-write、relay error丢partial stats。ADR-0011/0012已
  Accepted，SPEC/TEST amendments已Approved；T03 candidate `8f0d1e0`通过全部15项
  ticket commands（package 64、new filter 1/1），T06 candidate `756a379`通过全部
  ticket commands与package 33；两者scope/lineage/cleanliness检查PASS。T03
  Architect PASS、QA PASS_WITH_ACTIONS（唯一动作是T07后重跑quick）；T06 Architect
  PASS，但QA refined mutation证明read-ahead test在t=0无法排除read activity reset，
  test-only窄repair `0ef7969`以4s delayed read + final 1s original deadline杀死
  mutation。T03/T06分别经`951806d`/`2ce7708`合入local integration；组合
  Architect/QA均PASS，T03 64、T06 33、联合normal/all-features各97 tests及strict
  Clippy/fmt/locked metadata/scope/lineage/cleanliness均PASS，现均done。权威quick
  诊断仅因T07-owned两个`src/main.rs`缺失而未通过，不计PASS。T07保留`52dcdb0`
  并已恢复为`in_progress`。续作发现ADR-0012 required binary paused-time tests因
  两个binary manifests没有Tokio `test-util`且T07不拥有这些路径而无法编译；
  Product/Architect/QA triage均PASS exact two-dev-edge、zero-lock-delta方案；
  勘误base `24ddecf`的三方final document gates均PASS，ADR-0013现为Accepted。
  T07 candidate `5ac8f1b`完成exact dev edges、paused-time/native/lifecycle
  evidence；Architect发现cooperative row假阳性后，repair 1/2 `a9b0a56`用
  bounded target accept与EOF/reset ack关闭。ticket与integration
  Architect/QA均PASS，integrated `91516720`。T08 MSRV preflight暴露T07
  let-chain不兼容；窄repair `50bf0b7`与integration `123618f`通过Rust 1.85、
  focused、quick/full及final Architect/QA，T07 done。T08 checkpoint `14343d2`
  因sing-box evidence边界与静态Architect findings未集成；ADR-0014已在
  `96d6262`接受。repair 1/2 `5accd02`通过Engineer及QA的绝大部分本地执行，
  但final Architect/QA均**BLOCK**：external EOF/shutdown缺少跨线程顺序与
  production-bound mutations、partial I/O可越过absolute deadline、workflow
  policy非closed subset、platform helper存在false-pass/overclaim。repair 2/2
  现于`codex/repair/m0-t08-final-closure`集中关闭。QA首轮MSRV workspace的
  lifecycle flake经独立诊断确定为T07 harness端口ownership TOCTOU：
  `AddrInUse`可由foreign listener造成却被误认child ready；deterministic probe
  1/1复现。T07 first candidate `1974935`经Architect BLOCK后，follow-up
  `6139544`以causal metrics transition、absolute readiness deadline和显式
  failed-child/sibling cleanup关闭全部finding；Architect PASS、QA
  PASS_WITH_ACTIONS。T08 first final candidate `3d5b1a2`关闭workflow/platform
  findings后，follow-up `49c63082`补齐app EOF ack stream hold与fixed operation
  deadline；Architect PASS、QA PASS_WITH_ACTIONS。两者随后已在`51fb7327`
  组合并通过local same-SHA gates；首次hosted失败触发当前ADR-0015/T07/T08
  窄reopen。
- **Contract final verdicts:** 初始review要求exact 47-case matrix、
  `AddressBounds`、harness exact two-edge lock hunk、configured而非hardcoded
  durations、T03/T07 time-evidence ownership和完整ADR模板。全部修正后
  Product/Architect/QA最终均**PASS**，无BLOCKER/REQUIRED/advisory；
  `workflow.py doctor/validate/status/frontier/next`、locked metadata与
  `git diff --check`均exit 0。ADR-0013勘误base `24ddecf`的Product/Architect/QA
  final document gates均PASS；ADR-0013 implementation及T07 quick/full已在
  `91516720`通过。ADR-0014 proposal `f757b58`在causality wording收窄后获
  Product/Architect/QA final **PASS**，acceptance `96d6262`不改变pin/wire/
  product/API；T08 remote evidence仍不提前计PASS。
- **Ticket commits:** `ed2fc9243ceed8e2822319b22182f47936f4c22f`,
  `a13949998535a591f0f0a28542ac2b9bf5a25d15`,
  `cd51226cd1875f80115ac657526e3f9dfb267c14`,
  `4948185c0db282261e045ad1276f5e286f6d7d1d`
- **Commands, all exit 0:** `cargo +1.97.1 metadata --locked --format-version 1`;
  `cargo +1.97.1 test -p ferrum2-core --locked`;
  `cargo +1.97.1 test -p ferrum2-m0-harness --test architecture --locked`;
  `cargo +1.97.1 test -p ferrum2-m0-harness --test workspace_policy --locked`;
  `cargo +1.97.1 tree --workspace --locked`;
  `cargo fmt -p ferrum2-core -- --check`; `git diff --check`;
  focused architecture/workspace-policy CRLF regressions
- **Evidence:** core 4/4、architecture 6/6、workspace policy 7/7；integration
  worktree 最终 clean，无 committed generated artifact、external binary、secret
  或 production endpoint
- **Wave-2 commands, all exit 0:** T05 全部 5 个 ticket commands；T06 全部
  9 个 ticket commands；`cargo test -p ferrum2-socks5 -p ferrum2-runtime
  --locked`（36 passed）；组合 Clippy、fmt、metadata、package trees 和 fixed-base
  `git diff --check`。T06 shutdown regression 在修复后 10,240 次 ready-race
  观察为 0 post-shutdown accepts
- **Historical Wave-2 approved deferrals:** workspace-wide quick/full 等下游 target source 在 T07
  汇合后执行；MSRV、platform、interop 与 GitHub Actions evidence 属于 T08，
  此处不计 PASS
- **Remote at that checkpoint:** origin URL 与只读访问已验证；未 push、未触发
  Actions、未发布

## 规划前历史基线（非当前状态）

- **Branch/commit:** pre-amendment baseline
  `master@5402860136c3233ff1890080099dcddc7d321fee`
- **Date:** 2026-07-27（Asia/Shanghai）
- **Environment:** Microsoft Windows 11 专业版 64-bit，build `10.0.26200`；
  PowerShell `7.6.4`
- **Toolchain:** `stable-x86_64-pc-windows-msvc`；`rustc 1.96.0`；
  `cargo 1.96.0`；`rustfmt 1.9.0-stable`；`clippy 0.1.96`；
  Python `3.11.9`
- **Installed Rust targets:** `x86_64-pc-windows-msvc`,
  `x86_64-pc-windows-gnu`, `wasm32-unknown-unknown`；required Linux
  glibc/musl targets 当前未安装
- **Repository state before bootstrap edits:** clean `master`
- **Result:** 工作流控制面结构有效，但产品验证基线为 **BLOCKED**；没有 Cargo
  workspace、产品测试或 CI，不能描述为 CI green
- **M0 planning state:** ADR-0001～0007 Accepted，SPEC/TEST-0001 Approved，
  M0-T01～T08 ready；ADR-0007 已选择 GitHub Actions/GitHub-hosted runners，
  但 workflow 尚未创建、integration commit 尚未推送，产品与远程 CI gate 仍为
  BLOCKED/NOT_RUN
- **Remote observation:** 本地已有 `origin=https://github.com/zzffu/ferrum2.git`；
  本轮未修改 remote、未验证 push/Actions capability，也未推送。remote
  初始化/URL修正（若需要）与CI branch push仍需用户单独授权

## 规划前历史仓库与自动化清点（非当前状态）

- 无 `Cargo.toml`、`Cargo.lock`、Rust 产品源码、benchmark 或产品 test files；
- 无 `.github` CI workflow 或其他 CI definition；固定路径
  `.github/workflows/m0.yml` 只存在于 ADR/spec/test/ticket 合同；
- bootstrap 时无 non-template contract/ticket；M0 plan与本次amendment现有七份
  Accepted ADR、一份Approved spec、一份Approved test plan、八份ready ticket和
  一份upstream evidence note；
- pre-amendment Git history 为 `88f29f2`（control-plane 初始化）、`b41c612`
  （产品约束/validation commands）、`3024789`（M0 plan）和`5402860`
  （QA agent配置）；
- `workflow.toml` 是 host-local quick/full command 的 authoritative source；
  target matrix、interop、security 和 performance jobs 尚未实现。

## 规划前历史验证记录（非当前状态）

以下命令均在 `C:\project\ferrum2` 运行。退出码是当前 PowerShell/Codex runner
呈现的状态；Cargo 的共同 diagnostic 是找不到根 `Cargo.toml`。

| Date | Branch/commit | Command/job | Exit | Result/evidence |
|---|---|---|---:|---|
| 2026-07-27 | `master@b41c612` | `python3 .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 1 | WindowsApps `python3.exe` alias 未启动解释器且无输出；随后使用已安装的 `python.exe` |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；警告 `No non-template tickets found` |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Workflow validation passed；同一 ticket 警告 |
| 2026-07-27 | `master@b41c612` | `python .agents/skills/milestone-workflow/scripts/workflow.py bootstrap` | 0 | Bootstrap complete；没有缺失的控制面文件 |
| 2026-07-27 | `master@b41c612` | `cargo fmt --all -- --check` | 1 | 失败：`cargo metadata` 找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` | `cargo check --workspace --all-targets --locked` | 1 | 失败：找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` | `cargo test --workspace --locked` | 1 | 失败：找不到 `Cargo.toml` |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；仅有无 non-template ticket 警告 |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 更新后的四份 bootstrap 文档通过 workflow validation |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py status` | 0 | 仅四份预期文档为 dirty；`Milestones: no tickets` |
| 2026-07-27 | `master@b41c612` + bootstrap docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action: no_tickets`，bootstrap 后应进入 M0 plan |
| 2026-07-27 | `master@b41c612` + M0 plan docs working tree | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Workflow validation passed；8 tickets、documents、DAG 和 ownership 无 warning |
| 2026-07-27 | same | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0 --json` | 0 | 唯一 selected frontier 为 M0-T01；`skipped=[]`、`warnings=[]` |
| 2026-07-27 | same | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、`ready=8`、selected T01；T02-T08 均只等待显式 blockers |
| 2026-07-27 | same | `git diff --check` | 0 | 无 whitespace error；Git 仅提示既有 Windows LF→CRLF checkout policy |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 六 ADR、一 spec、一 test plan、八 tickets、DAG 和 ownership 全部有效，无 warning |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0 --json` | 0 | 唯一 selected frontier=`M0-T01`；`skipped=[]`、`warnings=[]` |
| 2026-07-27 | same, final M0 plan | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、8 ready；T02～T08 的等待原因与 ticket blockers 精确一致 |
| 2026-07-27 | same, final M0 plan | `git diff --check` | 0 | 无 whitespace error；Architect 与 QA 最终只读复核均为 PASS、无 BLOCKER/REQUIRED |
| 2026-07-27 | `master@5402860`，amendment preflight | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | `master@5402860`，amendment preflight | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | Existing M0 plan workflow validation passed |
| 2026-07-27 | `master@5402860` + M0 CI amendment docs | `git ls-remote https://github.com/actions/checkout.git refs/tags/v6.0.2` | 0 | upstream tag精确解析为`de0fac2e4500dabe0009e67214ff5f5447ce83dd`；只读查询，不访问或修改项目remote |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor` | 0 | Doctor checks passed；base=`master`、strategy=`drain`、unlimited waves、auto-close false |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | ADR-0007、SPEC/TEST、8 tickets、DAG与ownership有效，无warning |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py frontier --milestone M0` | 0 | 唯一selected frontier=`M0-T01` |
| 2026-07-27 | same, M0 CI amendment | `python .agents/skills/milestone-workflow/scripts/workflow.py next --milestone M0 --json` | 0 | `action=execute_frontier`、8 ready；T02～T08只等待原有ticket blockers；`warnings=[]` |
| 2026-07-27 | same, M0 CI amendment | `git diff --check` | 0 | 无whitespace error；仅有既有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final M0 CI amendment | Architect final read-only gate | PASS | ADR-0007/0006补充关系、provider/security/evidence、M3边界、ownership与remote授权边界一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, final M0 CI amendment | QA final read-only gate | PASS | AC→test→job→runner→timeout→command→evidence与FAIL/BLOCK一致；无BLOCKER/REQUIRED，仅记录既有LF→CRLF warning |
| 2026-07-27 | `master@b1c4e10` + ADR-0008 docs | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | 8 Accepted ADR、Approved SPEC/TEST、8 tickets、DAG与ownership有效，无warning |
| 2026-07-27 | same, ADR-0008 docs | `python .agents/skills/milestone-workflow/scripts/workflow.py status`；`next --milestone M0 --json` | 0 | `done=3, ready=5`；唯一selected frontier=`M0-T02`；`warnings=[]` |
| 2026-07-27 | same, ADR-0008 docs | archive/entry/spec/IPR SHA-256与numeric-case comparison | 0 | `511e…e07f0`、`4fff…137f1`、`6ceb…436a`、`327e…b6c37`、`0170…813d`精确；旧/新/upstream values一致 |
| 2026-07-27 | same, ADR-0008 docs | `git diff --check` | 0 | 无whitespace error；仅有既有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final ADR-0008 contract | Architect final read-only gate | PASS | partial supersession、source classification/hashes/rights、no-binary与no-behavior/scope-change完整；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, final ADR-0008 contract | QA final read-only gate | PASS | M0-CRYPTO-002/T02映射、numeric invariants、frontier与未执行gate状态一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | `master@5a3a89e` + final ADR-0010 contract | `python .agents/skills/milestone-workflow/scripts/workflow.py validate` | 0 | ADR/SPEC/TEST/T03/T07同步修订、DAG与ownership有效 |
| 2026-07-27 | same, final ADR-0010 contract | `git diff --check` | 0 | 无whitespace error；仅有Windows LF→CRLF checkout warning |
| 2026-07-27 | same, final ADR-0010 contract | Product / Architect / QA final gates | PASS | 无剩余BLOCKER/REQUIRED/advisory；wire/product/core/runtime/manifest范围不变 |
| 2026-07-27 | `master@ad9e499` + final ADR-0011/0012 contract | `python .agents/skills/milestone-workflow/scripts/workflow.py doctor`；`validate`；`status`；`frontier --milestone M0 --json`；`next --milestone M0 --json` | 0 | 12 Accepted ADR、Approved SPEC/TEST amendments；T03/T06 selected、T07 blocked、无warning |
| 2026-07-27 | same, final ADR-0011/0012 contract | `cargo metadata --locked --format-version 1`；`git diff --check`；ADR required-section/whitespace/bare-CR audit | 0 | 当前baseline 110 packages；两份ADR模板完整；无whitespace/bare-CR finding，只有既有autocrlf warning |
| 2026-07-27 | same, final ADR-0011/0012 contract | Product / Architect / QA final read-only gates | PASS | configured default/non-default deadlines、evidence ownership、47-case native、exact lock exception、partial accounting与scope一致；无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | `codex/integration/m0@2ce7708` | T03全部16项、T06全部9项、联合normal/all-features package tests、strict Clippy/fmt、locked metadata、scope/lineage/cleanliness | 0 | T03 64、T06 33、联合97/97；Architect/QA组合gate均PASS，无BLOCKER/REQUIRED/advisory |
| 2026-07-27 | same, pre-T07 diagnostic | configured quick：fmt/check/test | 1/101/101 | 仅缺T07-owned client/server `src/main.rs`；不计quick PASS，须T07汇合后重跑 |

三条 Cargo 失败是当前基线的预期、已记录 blocker，不是测试失败被豁免。full
commands 未运行，因为与 quick commands 具有同一个缺失 workspace 前置条件；
这不是 full gate pass。

## 当前 gate 状态

| Gate | 状态 | 证据/缺口 | 最早解除里程碑 |
|---|---|---|---|
| Workflow doctor/validate | PASS | exact material SHA上的doctor、validate、frontier/next与diff-check均exit 0；无open root | M0 |
| M0 execution contracts | IMPLEMENTED / PASS | 产品/security/platform/reference/exact-SHA结果不变；薄profile与Cargo-managed qualification已集成和review | M0 |
| GitHub Actions workflow | `30331336772` SUCCESS | exact `8318ef1`，attempt 1，整体及六项required results全部success | M0 |
| Local quick/full | PASS | exact `8318ef1` authoritative quick 3/3、full 4/4与workspace binaries build均exit 0 | M0 |
| Security/KAT/negative | PASS | exact `8318ef1`本地full及同SHA hosted `quality` success | M0 |
| Lifecycle/backpressure | PASS | exact `8318ef1`本地full及同SHA hosted `quality` success | M0 |
| External interop | PASS | 同一run/attempt的`interop` success；reviewed fail-closed aggregation要求两个setup成功、qualification exit 0及4/4 | M0 |
| Linux GNU/musl + Windows | PASS | 同一run/attempt三个explicit platform matrix cells全部success | M0 |
| Performance/10k idle | PASS, M4 CLOSED | exact `9b379a4` run `30730883667/1`完成throughput、THP apply/restore、10k、180/180、6/6、drain及cleanup；同run final qualification通过，吞吐比仍仅作诊断 | M4 |

## 已实现并通过的 M0 CI profile

唯一 workflow 是 `.github/workflows/m0.yml`。trigger 只允许
`pull_request`、push 到 `master`/`codex/integration/**` 和
`workflow_dispatch`，禁止 `pull_request_target`。checkout 固定
`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`、full history；
permissions 只有 `contents: read`，所有 `uses:` 为 full SHA。required jobs
不使用 cache、secrets、cross-job ferrum artifacts或 `continue-on-error`。

| Definition | Runner / cells | Evidence group |
|---|---|---|
| `quality` | `ubuntu-24.04` | workspace binary build + `workflow.toml` full；security/lifecycle/local E2E只运行一次 |
| `msrv` | `ubuntu-24.04` | Rust 1.85.0 all-target check + actual workspace tests |
| `platform` | Windows MSVC、Linux GNU、Linux musl explicit matrix | 两个release artifacts、四次config；GNU/Windows detection；musl static |
| `interop` | `ubuntu-24.04` | Cargo-managed non-test driver固定报告M0-INT-001～004，4/4 |

四个definitions展开六个rendered results；name/count不是永久产品合同。每个job
必须从clean VM/current `GITHUB_SHA`构建并记录runner label、ImageOS、
ImageVersion、OS/kernel、rustc/cargo；platform cells另记录artifact hash/linkage。
GitHub-hosted VM没有OCI image digest，provider-native evidence只用于M0 smoke，
不是M3 qualification。required job启动后失败为FAIL；workflow、
provider、未授权push或job未产生结果为BLOCKED；missing/skipped均非PASS。

M0 close只接受另行授权push后的一个exact integration SHA、一个run ID/attempt中
六个预期rendered results及完整workflow全部success。诊断artifact必须脱敏；
packet capture、benchmark output、
coverage/profiling output 和 rendered docs 属于 generated artifacts，不提交仓库。

## 已知缺口、flakes 与 skipped coverage

- Remote run `30331336772`已在exact `8318ef1`真实执行并整体success，六项结果
  均来自同一attempt。旧`30322690937`与`30301746374`继续保持失败历史，不追认、
  不拼接。
- Windows 上技能文档给出的 `python3` 命令不可用；当前可复现入口是 `python`。
  是否修改 workflow helper 的跨平台调用说明留待单独控制面决策，不阻塞本次文档。
- M0 已固定build compiler 1.97.1、MSRV 1.85.0 check/test、三个target
  triples、reference versions/checksums、fixture provenance、GitHub
  runner/security和unavailable=FAIL/BLOCK contract；job topology不再固定。
  T09/T10实现、exact-SHA local/review gates及同一run/attempt六项success均完成。
- `origin/codex/integration/m0`现精确指向`8318ef1`；一次性push授权已耗尽。
  master remote、PR、tag、release、branch protection、rerun、第二次push及其他
  remote mutation仍未授权。
- SPEC/TEST-0005固定的driver、workflow job、bounded 10k-idle threshold和
  comparison statistics已由exact `9b379a4` run `30730883667/1`全部通过；本机/
  WSL2仍仅作diagnostic，不能替代该hosted PASS。
- M0 closeout已重新执行workflow doctor/validate、release dependency checks、
  exact-SHA full gate和`git diff --check`；最终里程碑状态与恢复入口记录在
  `docs/handoffs/HANDOFF-M0-2026-07-28.md`。
