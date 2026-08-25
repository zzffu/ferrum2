# M17 Windows TUN qualification runbook

M17 is the privileged acceptance gate for the managed Windows TUN. This runbook also includes the
separate durable M16 hard-kill release gate and the deterministic TUN fuzz-smoke gate; neither is an
M17 mode. The
authoritative controller is
[`tests/platform/qualify_windows_tun.ps1`](../tests/platform/qualify_windows_tun.ps1), and the
only approved M17 and fuzz-smoke entry point is the local
[`run_windows_tun_hyperv.ps1`](../tests/platform/run_windows_tun_hyperv.ps1) orchestrator. This
runbook governs its host build, bounded staging, identity evidence, artifact readback, cleanup, and
final checkpoint restoration around the tracked
[TUN configuration contract](config-v2-tun.md) and
[network-model v2 migration contract](network-model-v2-migration.md).

## Safety boundary

The qualification controller creates and removes adapters, addresses, routes, and DNS settings.
Run it only inside the approved Hyper-V guest. Never run any mode, including `cleanup`, on the
Hyper-V host or on a developer workstation. The host is limited to building the exact candidate,
exact-ID VM lifecycle control, staging or exporting files, and recording read-only evidence. It must
not create, remove, or alter a host adapter, address, route, DNS setting, firewall rule, or TUN
session.

The approved VM and qualification checkpoint are selected only through the external, hash-pinned
support-topology manifest. The currently provisioned topology is:

| Object | Required name | Required ID |
|---|---|---|
| VM | `Windows 10 MSIX packaging environment` | `82e20295-1d30-48e7-a751-e21d35d872d4` |
| Qualification checkpoint | `Ferrum2-WindowsTun-InternalSupport-v1` | `fecf1eaa-7e8f-457d-b193-8b451859ac13` |
| Internal support switch | `Ferrum2 TUN Support` | `05cbc0b1-66ab-45bc-b537-8fcb4b897708` |

The manifest normally lives at
`%LOCALAPPDATA%\Ferrum2\windows-tun-support-topology.json`; pass its exact lowercase SHA-256 with
every invocation. The currently provisioned manifest SHA-256 is
`61cd6a446d11ab54459f7c59027d6dc2c446ca86c5358eb57e56754f4dd10ea8`. Its isolated support path is
`192.168.250.1/30` on the host and `192.168.250.2/30` on guest interface `Ferrum2Support`, with MTU
1500 and no gateway, DNS, NAT, or ICS. The retained management adapter may remain connected to
`Default Switch`, but qualification support traffic must not select it.

Do not substitute a VM selected only by name, a checkpoint selected as "latest", or a newly created
checkpoint. Keep the approved VM `Off` outside the bounded qualification window. Credentials belong
in the external orchestration secret store; never place them in the repository, identity ledger,
command line, logs, or artifacts.

On the authorized Hyper-V host, the orchestrator reads the exact manifest, validates its provenance,
and resolves and cross-checks the approved topology before any mutating command. The essential
identity portion is equivalent to:

```powershell
$approvedVmId = [guid]'82e20295-1d30-48e7-a751-e21d35d872d4'
$approvedVmName = 'Windows 10 MSIX packaging environment'
$approvedCheckpointId = [guid]'fecf1eaa-7e8f-457d-b193-8b451859ac13'
$approvedCheckpointName = 'Ferrum2-WindowsTun-InternalSupport-v1'

$vm = Get-VM -Id $approvedVmId -ErrorAction Stop
if ($vm.Name -cne $approvedVmName) { throw 'approved VM identity mismatch' }
$checkpoint = @(Get-VMSnapshot -VM $vm -ErrorAction Stop |
    Where-Object { $_.Id -eq $approvedCheckpointId })
if ($checkpoint.Count -ne 1 -or $checkpoint[0].Name -cne $approvedCheckpointName) {
    throw 'approved checkpoint identity mismatch'
}
```

Before staging every supported M17, fuzz-smoke, or hard-kill profile, the user-facing process
requires the VM to be `Off` and captures immutable cleanup authority for the exact VM ID/name,
checkpoint ID/name, and source-parent ID. It also revalidates the manifest, support listener,
Internal switch, host and guest support adapters, return path, and protected host TUN identity. It
then launches one hidden, capability-bound worker for the complete VM-active phase. The worker must
match the supervisor PID, process start time, executable, and one-use 64-hex token before it can do
any work. The worker blocks on a unique named start gate; the supervisor releases it only after
assigning the process to a Windows kill-on-close Job Object and reading back exact job membership.
It streams stdout and stderr under separate 16 MiB caps, requires the Job's active-process count to
return to zero, and applies monotonic outer timeouts: 30
minutes for probe-only, two hours for ordinary qualification and hard-kill, and three hours for a
`*-1000` profile.
The bounded Hyper-V Read/Start/Stop/Restore helpers use the same membership-before-release gate and
kill-on-close Job rule, so a helper cannot begin a VM operation before its supervisor owns it.

Run the ten M17 invocations and the separate fuzz-smoke and hard-kill invocations serially. A full
worker must export its closed evidence, stop the exact VM, restore the exact checkpoint, stop again,
and prove final `Off`. The supervisor accepts exactly one terminal record and independently reads
back the exact VM ID/name/state. On timeout, malformed output, nonzero exit, or failed readback, it
first terminates the complete worker Job, then performs bounded exact-GUID recovery. It never selects
a VM or checkpoint by a similar name or by “latest” snapshot. Do not retry or continue after any
identity, execution, cleanup, export, restore, topology, support-listener, or final-state failure.
The runner never starts, stops, or reconfigures the externally provisioned support listener.

This recovery guarantee covers failures detected while the user-facing supervisor is alive. If that
supervisor is forcibly terminated, its kill-on-close Job stops the worker and descendants, but no
remaining process can restore the checkpoint or prove the VM `Off`; host power loss has the same
boundary. Treat either event as an abandoned run: do not rerun qualification, first re-resolve the
exact approved VM/checkpoint IDs and complete the bounded recovery sequence below. Never infer
cleanup from worker disappearance alone.

Restoring the checkpoint destroys unexported guest changes. Export artifacts before the final
restore.

## Candidate and identity ledger

The local host gate must use the repository-pinned Rust 1.97.1 toolchain, locked dependencies, a
clean checkout, and one exact candidate commit. Build the client, server, the three exact test
harnesses, and the standalone Windows smoke executable from that commit on the host:

```powershell
git status --porcelain
git rev-parse HEAD
rustup toolchain install 1.97.1 --profile minimal
cargo +1.97.1 build -p ferrum2-client -p ferrum2-server --bins --locked
cargo +1.97.1 test -p ferrum2-client --bin ferrum2-client --no-run --locked
cargo +1.97.1 test -p ferrum2-tun --lib --no-run --locked
cargo +1.97.1 test -p ferrum2-wintun --lib --no-run --locked
cargo +1.97.1 build --manifest-path crates/ferrum2-tun/fuzz/Cargo.toml `
    --bin smoke --no-default-features --locked --target x86_64-pc-windows-msvc
```

The status must be empty, and `HEAD` must be the lowercase 40-hex `candidate_sha` recorded below.
Stage Wintun 0.14.1 separately. Its ZIP SHA-256 must be
`07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51`; the controller also requires
the AMD64 DLL SHA-256
`E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`, valid Authenticode trust, and
the closed export set embedded in the controller.

The host-issued identity ledger is a trust boundary, not a free-form note. It must be canonical
compressed JSON encoded as UTF-8 without BOM, on exactly one line, terminated by exactly one LF.
Its properties must appear in this order:

```text
schema, vm_name, vm_id, checkpoint_name, checkpoint_id,
guest_product, guest_edition, guest_architecture, guest_version, guest_build,
candidate_sha, probe_sha256, client_sha256, server_sha256, support_listener,
topology, test_binaries
```

`schema` is integer `2`; VM and checkpoint values must exactly match the manifest and table above;
`guest_architecture` is `AMD64`. `probe_sha256` is the lowercase SHA-256 of the exact staged
`qualify_windows_tun.ps1`; the client and server fields are the lowercase SHA-256 values of the exact
staged executables. Guest product, edition, version, and build must match live OS readback. The
`topology` object has exactly these properties in order:

```text
manifest_sha256, plan_sha256, support_switch_id, support_host_ipv4,
support_network, support_prefix_length, guest_interface_alias,
guest_interface_guid, guest_interface_index, guest_mac_address, guest_ipv4,
guest_mtu_bytes, protected_host_tun_name, protected_host_tun_guid,
protected_host_tun_index, protected_host_tun_status
```

Every topology value is copied from the exact external manifest and is cross-checked against live
host and guest state before and after execution. The protected-host-TUN fields prove that the host's
existing sing-box `tun0` was neither used nor changed.

The `support_listener` object has exactly `ipv4`, `tcp_port`, `udp_port`, `pid`, `owner`,
`executable_sha256`, and `creation_utc`, in that order. `ipv4` must equal the manifest's support host
address. The same PID and owner must own the exact TCP port and four consecutive UDP ports beginning
at `udp_port`; its executable hash and process creation time must match live host readback. This
listener is an externally provisioned, read-only dependency of the gate. `creation_utc` uses the
canonical six-fractional-digit UTC form `yyyy-MM-ddTHH:mm:ss.ffffffZ`; this preserves an exact
PowerShell 7.4 JSON round trip.

`test_binaries` is a required final property containing exactly `client`, `tun`, and `wintun`
lowercase SHA-256 values in that order. The host runner repeats the locked `--no-run` builds, stages
the three harnesses under fixed names, and compares every hash with the ledger before starting the
VM. The smoke executable is not added to this already-issued ledger schema: its exact SHA-256 and
size are instead bound to the clean `candidate_sha` by staged-input schema v3, read back by the guest,
and copied into guest/host result evidence. The host only compiles and stages this executable; it
never runs it. The approved guest runs the prebuilt executable without Git, Cargo, rustup, or a Rust
compiler.

Record the SHA-256 of the complete ledger bytes as `identity_sha256`. Do not edit or reserialize the
ledger after hashing it. The controller independently verifies its closed property set, canonical
serialization, exact VM/checkpoint identity, guest build, candidate and binary hashes, support
listener boundary, and the ledger hash reported in M17 or hard-kill evidence.

Use a unique `RunToken` matching `^[A-Za-z0-9][A-Za-z0-9-]{0,47}$` for every invocation. The local
host wrapper requires its profile-specific artifact directory to be absent and then creates it. For M17,
the controller accepts that existing non-reparse directory outside
`%TEMP%\ferrum2-m17-tun-<RunToken>` only when its four controller-owned JSON baselines are absent.
The hard-kill wrapper owns a separate `ferrum2-hard-kill-<RunToken>` directory and does not pass it to
the controller. Never reuse a token after success or failure.

## Required mode matrix

There are six supported logical M17 controller modes. Ordinary network reset and restart stress each
have three required cycle counts, producing ten M17 release-evidence invocations. The separately
versioned M16 hard-kill gate and deterministic TUN fuzz-smoke gate each add one required profile, for
twelve local release-evidence invocations in total.

| Gate | Host profile | Controller invocation | Contract coverage | Required witnesses/cases | Exact tests |
|---|---|---|---|---:|---:|
| M17 | `network-reset-10` | `-Mode network-reset -NetworkResetCycles 10` | Ordinary notification/ResetNetwork smoke with exact PID, adapter, managed-state, metric, JSONL, and WFP identity readback | 15 | 16 |
| M17 | `network-reset-100` | `-Mode network-reset -NetworkResetCycles 100` | Standard ordinary ResetNetwork lifecycle stress | 15 | 16 |
| M17 | `network-reset-1000` | `-Mode network-reset -NetworkResetCycles 1000` | Ordinary ResetNetwork endurance with bounded WFP snapshots | 15 | 16 |
| M17 | `restart-10` | `-Mode restart-stress -RestartCycles 10` | Same-process restart smoke and exact cleanup baseline | 5 | 4 |
| M17 | `restart-100` | `-Mode restart-stress -RestartCycles 100` | Standard lifecycle stress | 5 | 4 |
| M17 | `restart-1000` | `-Mode restart-stress -RestartCycles 1000` | Endurance lifecycle stress | 5 | 4 |
| M17 | `fragments` | `-Mode fragments` | IPv4/IPv6 UDP and TCP reassembly, extensions, atomic fragments, DNS, overlap, timeout, disabled family, stale generation | 9 | 9 |
| M17 | `dual-stack-dns` | `-Mode dual-stack-dns` | IPv4-only, IPv6-only, and dual TCP/UDP synthetic DNS plus readback/restore | 7 | 2 |
| M17 | `udp-policy` | `-Mode udp-policy` | Source-keyed EIM and route-once association policy; ADF/EIF; parsed DNS, QUIC Initial, STUN/WebRTC, and game-style payloads; multi-target and v4/v6 source coverage; capacity, queue-pressure, and restart-stale-state contracts; directed-broadcast isolation; journaled firewall masking control | 18 | 9 |
| M17 | `scheduler-ring-full` | `-Mode scheduler-ring-full` | Exact TCP 8/16/64 capacity-aware rotation, live UDP sequences totaling 8/16/64 in bounded eight-packet batches, a 256-packet 1,200-byte live egress pressure stage with closed sent/drop accounting, fair work rotation, lossless response backpressure, explicit nonfatal ring-full drop, and closed Wintun owner error dispositions | 8 | 8 |
| TUN fuzz smoke | `fuzz-smoke` | guest executes staged `ferrum2-tun-fuzz-smoke.exe` | Four packet-reassembly, three UDP-reset race, eight removed-config, and eight strict-route rule-plan seeds plus bounded empty/malformed/oversized inputs and exact terminal/hash evidence | 23 | 0 |
| M16 hard-kill | `hard-kill` | `-Mode hard-kill` | Managed auto-route, auto-DNS, and mixed live-traffic processes are forcibly terminated; the two DNS cases bind the live strict-route WFP session, sublayer, owner PID, and eight filters before termination and prove their absence afterward, in addition to exact process, adapter, address, route, and DNS absence | 3 | 0 |

Each network-reset profile creates one journaled guest-underlay `/32` notification route and then
alternates its metric. This is an ordinary route/interface notification, not damage to Ferrum2-owned
state. Every cycle must retain the same client PID, adapter GUID/LUID/index, addresses, managed
routes, DNS, MTU, strict-route dynamic WFP session, sublayer, and eight exact filter IDs. Network and
session generation plus successful ResetNetwork counters advance exactly once per cycle; retry,
reset-failure, strict-route reinstall, and full-rebuild counters remain at baseline.
`network-reset-cycles.jsonl` contains exactly 10, 100, or 1,000 LF-terminated closed rows and remains
at most 1 MiB. The runner revalidates every row and takes 11/12/12 total WFP snapshots respectively,
including the baseline, without retaining the temporary XML state dumps.

The `fuzz-smoke` row is a separate in-memory deterministic gate. Hosted CI may compile fuzz targets
but does not execute them. The local host builds `smoke.exe` for
`x86_64-pc-windows-msvc`, stages it under the same candidate/manifest/hash trust chain as the M17
artifacts, and never executes it. Only the exact approved guest runs it. Acceptance requires exit
zero, empty stderr, the exact `TUN state smoke corpora: 4 packet, 3 UDP reset, 8 config legacy, and 8 strict-route seeds passed`
terminal, and a closed result
binding the executable SHA-256/size, candidate SHA, identity SHA, staging-manifest SHA, seed counts,
and log hashes.

Each hard-kill case installs one managed IPv4 `/32` capture route for the identity-ledger support
listener. The mixed case still sends real TUN TCP and UDP echo traffic, issues the proxy SOCKS
CONNECT attempt, and exercises system DNS. The controller reads back the exact managed `/32`, next
hop, and route metric before termination. This is owned-route evidence, not external route-conflict
or kill-switch evidence.

For `auto-dns` and `mixed`, strict-route requested/effective metrics must each equal exactly `1`,
filter-install success must equal exactly `1`, and filter-install failure must equal `0`. Immediately
before `TerminateProcess`, a bounded WFP state snapshot must bind the candidate owner PID, fixed
dynamic-session key/name, independent fixed sublayer key/name, managed adapter LUID, and all eight
fixed filter keys with unique nonzero dynamic IDs. After process exit, a second bounded snapshot
must contain no match for the captured session, sublayer, fixed filter keys/names, or dynamic IDs.
The mixed system-DNS witness must reach the guest-local responder exactly once and remain quiet for
500 ms after the response.

This strict-route guard covers ordinary TCP and UDP DNS on port 53. It is not a global zero-leak
kill switch and does not claim to block or observe DoH, DoT, or other encrypted DNS transports. The
guest-local responder count proves the intended resolver path and absence of a retry; it is not by
itself packet-capture proof that no physical interface saw any packet.

All three network-reset counts, all three restart counts, fuzz smoke, and the separate hard-kill
gate are required. A lower cycle count does not stand in for a higher count. Run all profiles
serially against this single approved guest; do not run concurrent jobs. Neither fuzz smoke nor
hard-kill may be reported as an M17 witness or used to replace any of the ten M17 invocations.

Execution status: `WINDOWS_EVIDENCE_IN_PROGRESS`. The table is the required release matrix, not a
record that any live VM row has passed. Do not mark this gate complete until all twelve exported
artifact sets, token/identity-bound readbacks, applicable cleanup results, and the final checkpoint restore have
been accepted. Performance calibration is a separate gate and remains `CALIBRATION_REQUIRED`; M17
correctness evidence cannot be used as performance acceptance. Its distinct entry point is
[`run_windows_tun_performance_hyperv.ps1`](../tools/run_windows_tun_performance_hyperv.ps1), governed by
[`windows_tun_performance_policy.json`](../tools/windows_tun_performance_policy.json); the current
policy's calibration and threshold fields are all `null`. The closed plan has nine scenarios and
90 alternating trials. Ten `udp-route-once` raw sidecars bind the real two-generation, 64-source,
four-target guest traffic and product association/router counter deltas; ten lifecycle sidecars
remain separate. The Wintun egress-pressure trial samples
`ferrum2_tun_pending_udp_responses` while the guest workload is running and records the observed
peak, not a configured or fabricated constant. It also records the raw workload-attempt,
successful-egress, ring-full-drop, derived response-attempt, and pending-response counts. The
validator derives `response attempts = successful egress + ring-full drops`, requires a bounded
minimum sample of 32,768 responses, recomputes the drop rate from those raw counters, and accepts a
natural zero-drop observation. That floor keeps the approximate 95% rule-of-three upper bound below
100 drops per million when zero drops are observed. A zero parent and zero candidate are a tie; a
zero parent followed by a positive candidate uses a signed 100 percent sentinel in the metric's
declared direction, not a claimed
percentage ratio. Calibrated thresholds for these zero-capable metrics must include that sentinel.
This performance trial therefore measures the real
Wintun egress pressure window; it does not claim that the live driver must reach ring-full on
every scheduler run. Ring-full classification, drop-without-retry, and absence of reset/rebuild
remain separate M17 correctness obligations. The M17 live pressure stage closes
successful-egress plus ring-full-drop accounting but likewise does not require a nonzero drop
count.
The performance runner uses the same `-PowerShellZip` parameter, external default path, exact
PowerShell version, and SHA-256 boundary documented under Local Hyper-V execution below.

Establish calibration from a qualification-baseline commit that already contains the complete
network-model implementation, route/cache metrics, collector, reducer, and schema. Run the first
`calibration-aa` with that same commit as both `ParentSha` and `CandidateSha`; this measures noise
only and cannot support an improvement claim. For a later comparison, keep that qualification
baseline as `ParentSha` and use a descendant optimization commit as `CandidateSha`. Do not use an
earlier commit that lacks the required route or cache metrics: the current collector deliberately
fails closed on those missing series, so such a run is neither a valid calibration nor a valid
performance comparison.

The approved checkpoint exposes one Hyper-V network adapter, so it cannot honestly demonstrate a
physical Wi-Fi-to-Ethernet handover. Interface resolver and notification unit tests may provide
deterministic contract evidence, but this
single-NIC guest must not be relabeled as a physical multi-adapter or handover qualification.

The UDP policy profile creates one temporary `ActiveStore` inbound UDP allow rule scoped to local
`198.18.0.2` and the exact staged PowerShell controller executable, with UDP `LocalOnlyMapping`
enabled. Windows otherwise infers non-TCP firewall sessions from both endpoint ports and can mask
Ferrum2's ADF/EIF decision when a response arrives from a new endpoint. The rule deliberately uses
remote `Any` because Windows may classify a Wintun-injected packet before the inner TEST-NET source
is available to the firewall rule; the exact program and synthetic local address keep the exception
inside the isolated qualification process. The controller journals and reads back every scope and
mapping property, removes the rule before profile completion, and the token-scoped recovery path
must read it back absent.

That profile uses only the journaled TEST-NET loopback targets already owned by the controller plus
the identity-ledger-approved external UDP echo listener. One bound IPv4 application socket sends
valid DNS and STUN messages, a structurally parsed 1,200-byte QUIC v1 Initial envelope, and
sequenced binary peer datagrams to multiple targets. Its first ordinary datagram selects the proxy
route once. A later target also matches an independent Direct rule, but the live association must
reuse the first frozen route and outbound. A distinct IPv6 source sends a valid ICE
connectivity-check request with `USERNAME`, `PRIORITY`, `ICE-CONTROLLING`, short-term
`MESSAGE-INTEGRITY`, and final `FINGERPRINT`. Every live payload is parsed before transmission,
echoed byte-for-byte, and hashed into the evidence row.

Ordinary request/response exchanges must reach the bound application socket. For the deliberately
unsolicited ADF/EIF probes, the controller instead closes the live product boundary at the Wintun
send counters: an accepted response increments egress exactly once without a filter or queue-full
increment, while a rejected response increments the filter counter exactly once and leaves the
socket quiet. The TEST-NET target address is also owned by guest loopback, so Windows may reject
that address as a source after Ferrum2 has successfully injected it through another interface. If
Windows does expose the datagram, the controller additionally validates its source endpoint and
payload. The exact prebuilt `c19_eim_adf_eif_and_actual_response_source_are_enforced` test, executed
in the same profile, remains the mandatory emitted-source-tuple assertion.

With `max_udp_mappings = 2`, the live profile fills one IPv4 and one IPv6 source-keyed association,
attempts a third source, requires the association-limit counter to advance without a target request,
and then requires the original source to echo again. Route-once immutability, queue-pressure, and
reset-stale-state witnesses come from exact prebuilt Rust candidate tests: synthetic DNS is handled
before the first ordinary route, the resulting plan stays immutable while one egress serves multiple
targets, congested request/response queues retain lifecycle control, and old-generation candidates,
closes, and responses cannot affect a reused slot. These deterministic witnesses are not inferred
from live timing.

The scheduler profile uses the minimum accepted 128 KiB Wintun ring. After the lossless 8/16/64
bursts it withholds application reads while 256 echoed 1,200-byte datagrams reach the egress path.
The live evidence requires every response attempt to be accounted for exactly as either successful
egress or `DroppedRingFull`, requires every successful egress to reach the bound socket once, and
requires zero network resets and zero full rebuilds. Ring saturation is timing-dependent and is not forced into a live
pass; the exact injected candidate test always exercises the full branch and proves one-packet
drop, no retry, and no network lifecycle transition.

The raw ingress counter includes every frame Windows emits through the adapter, including rejected
OS control traffic unrelated to the bound test sockets. The burst oracle therefore requires the
accepted ingress and successful egress deltas to be exactly 8 + 16 + 64, and requires the target and
client payload sets to match exactly. Raw ingress, rejected ingress, and the non-accepted difference
remain explicit evidence fields; they are never relabeled as accepted workload or silently added to
the burst count.

## Local Hyper-V execution

Run each of the ten supported M17 profiles and the separate `fuzz-smoke` profile through the host
orchestrator. The credential argument
may be omitted when a `PSCredential` exported by the current host user with `Export-Clixml` exists at
`%LOCALAPPDATA%\Ferrum2\hyperv-ferrum2-test.credential.xml`. Keep that DPAPI-protected file outside
the repository and evidence directories. All three Hyper-V entry points also default to the official
PowerShell 7.4.19 win-x64 archive at
`%LOCALAPPDATA%\Ferrum2\PowerShell-7.4.19-win-x64.zip`. The archive must remain outside the repository
and its SHA-256 must be
`cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9`; use `-PowerShellZip` only to
select another absolute location containing those exact bytes:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_hyperv.ps1 `
    -Profile fragments `
    -RunToken '<unique-token>' `
    -TopologyManifestPath "$env:LOCALAPPDATA\Ferrum2\windows-tun-support-topology.json" `
    -TopologyManifestSha256 '<exact-lowercase-manifest-sha256>' `
    -SupportTcpPort 44150 `
    -SupportUdpPort 44160 `
    -SupportPid '<exact-live-pid>' `
    -SupportOwner '<exact-live-owner>' `
    -IdentityLedger '<absolute-host-ledger-path>' `
    -WintunZip '<absolute-wintun-0.14.1-zip-path>' `
    -PowerShellZip '<absolute-PowerShell-7.4.19-win-x64-zip-path>' `
    -EvidenceDirectory '<absent-absolute-host-evidence-path>'
```

Run M16 hard-kill only through its independent host orchestrator. It has no `Profile` parameter and
must not be added to the M17 runner's profile set:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_hard_kill_hyperv.ps1 `
    -RunToken '<unique-token>' `
    -TopologyManifestPath "$env:LOCALAPPDATA\Ferrum2\windows-tun-support-topology.json" `
    -TopologyManifestSha256 '<exact-lowercase-manifest-sha256>' `
    -SupportTcpPort 44150 `
    -SupportUdpPort 44160 `
    -SupportPid '<exact-live-pid>' `
    -SupportOwner '<exact-live-owner>' `
    -IdentityLedger '<absolute-host-ledger-path>' `
    -WintunZip '<absolute-wintun-0.14.1-zip-path>' `
    -PowerShellZip '<absolute-PowerShell-7.4.19-win-x64-zip-path>' `
    -EvidenceDirectory '<absent-absolute-host-evidence-path>'
```

The non-mutating parameter/schema contract can be inspected without resolving a credential,
building artifacts, inspecting a VM, or starting guest execution:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_hard_kill_hyperv.ps1 -DescribeContract
```

Before any VM mutation, the orchestrator verifies the exact candidate commit, repeats the locked
host builds, compares the client/server/test hashes with the ledger, compiles but does not execute the
Windows fuzz-smoke binary, verifies and stages the pinned PowerShell 7.4.19 archive, and stages
bounded Visual C++ runtime libraries. It then restores the exact approved checkpoint, starts the
exact VM, and copies
only the controller, identity ledger, exact topology manifest, guest path probe, Wintun archive,
precompiled executables, portable PowerShell archive, runtime libraries, and a hash-bound staging
manifest. Before the first guest TUN is created, the probe proves that the support address selects
the exact direct `/30` route, source address, support interface identity, MAC, and MTU, with no
gateway or DNS configuration. For M17, the guest expands portable
PowerShell and invokes the controller with explicit
`ClientBinary`, `ServerBinary`, `CandidateTestDirectory`, `RuntimeLibraryDirectory`, and `WintunZip`
paths. For `fuzz-smoke`, it directly runs only the manifest-verified smoke executable. No guest
checkout, dependency resolution, toolchain installation, or Rust build is permitted.

The controller and outer orchestrator both run token-scoped cleanup. Guest evidence is rejected if
it contains a reparse point, more than 512 files or 128 directories, a file larger than 64 MiB, or
more than 512 MiB in total. The host exports evidence before it turns off the VM, restores the same
checkpoint again, verifies the final state is `Off`, and only then publishes the host orchestration
manifest.

The adjacent `hard-kill` gate retains its separately versioned artifact and cleanup contract; do not
adapt the M17 host-runner command by changing only `Profile` to `hard-kill`.

For M17, the main controller also performs bounded cleanup in its own `finally`; the outer cleanup is an
additional idempotent, ownership-checked reap. `%ProgramData%\Ferrum2\ControllerRunIdentities\<token>.json`
is an ACL-restricted, atomically published, closed-schema identity journal that includes the M17
identity hash and deliberately remains until this outer reap. Work-local journals separately identify
owned target addresses, the staged Wintun DLL, the network-reset notification route, and the bounded
UDP firewall exception. Mutation intents are flushed before the mutation and are consumed only after exact ownership readback; unknown or
changed state fails closed. The outer reap deletes the ProgramData journal only after process,
adapter, DLL, address, route, metric, mutation-journal, and work-directory readback succeeds. Only
after those mutations are reaped does it validate the artifact-embedded ledger and result against
the durable journal; a missing or corrupt original ledger path cannot block state cleanup. It
flushes recoverable pending evidence, deletes the ProgramData journal, and atomically publishes
`external-cleanup.json`. Do not replace it with broad process kills or
name/glob-based route, adapter, or filesystem deletion.

Hard-kill uses the same token-scoped identity journal and controller ownership rules, but the outer
cleanup consumes that journal without requesting M17 artifact publication. The hard-kill wrapper
then checks
the exact client/server executable paths together with `--config` and one of the four token-scoped
controller work prefixes; all five exact adapter names; the controller target-address and route
allowlist; adapter DNS rows; the owned sibling DLL; work and mutation-journal directories; the exact
token firewall rule; and completed or pending identity journals. Every count must be zero.

## Artifact acceptance

Every M17 run must preserve `identity-ledger.json`, `m17-contract.json`, `m17-result.json`,
`external-cleanup.json`, all bounded-command and candidate/server process logs emitted under the
artifact directory, and exact-test stdout/stderr. Preserve the host orchestration manifest as
controller-console evidence. Hash the four JSON files after export, and retain those hashes with the
candidate SHA, manual run token, mode, cycle count, and UTC collection
time. Network-reset runs must additionally preserve `network-reset-cycles.jsonl`.

The local wrapper also preserves staged-input schema
`ferrum2.windows-tun.hyperv-staged-input.v3`, guest-run schema
`ferrum2.windows-tun.hyperv-guest-run.v4`, and
`host-orchestration.json` schema `ferrum2.windows-tun.hyperv-host-run.v4`. Together they bind every
staged executable/runtime archive—including fuzz smoke—the exact profile/mode and both nullable cycle
fields, the staging-manifest hash, exported file hashes, exact topology manifest, live support
listener and guest support path, VM/checkpoint identities, unchanged host TUN, zero host-network
mutations, and final `Off` state.

The host manifest is published only from the fixed sibling
`host-orchestration.pending.json` in the same evidence directory. The writer uses create-new bytes
and `Flush(true)`, validates the closed document and a fresh `evidence_files` hash set, performs a
same-volume atomic move to `host-orchestration.json`, then rereads the final bytes and recomputes the
fresh evidence hashes. Both manifest names are excluded from `evidence_files`, and success requires
the pending name to be absent. If the outer supervisor rejects the worker, it deletes the exact
pending file and any PASS or invalid final manifest; a schema/token/VM-bound `status: fail` final may
remain for diagnosis. Other token-scoped failure evidence is retained.

Accept a run only when all of the following are true:

1. `m17-contract.json` has schema `ferrum2.windows-tun.m17-contract.v2`, status
   `preflight_pass`, the requested mode/cycle count, exact approved VM/checkpoint names and IDs,
   guest build, exact topology and guest support-path preflight, pinned Wintun hashes, and hashes
   matching the embedded identity ledger. Its
   `controller_sha256` equals the ledger `probe_sha256`; optional test-binary hashes match it too.
2. `m17-result.json` has schema `ferrum2.windows-tun.m17-result.v2`, status `pass`, the requested
   mode, unique run token, expected `network_reset_cycles` or `restart_cycles` value with the other
   cycle field `null` (both are `null` for non-cycle modes), exact approved
   VM/checkpoint identity and guest build, and the same identity, candidate, client, server,
   controller, Wintun, and test-binary hashes as the contract.
3. Every fixture reports `offline_check: pass`, and fixture names and hashes match the preflight
   contract. Every deterministic test reports `status: pass`, executed exactly one test, and the
   count matches the table.
4. The result witness names are exactly the contract witness set—no missing, duplicate, or extra
   name—and every witness reports `status: pass`. Required live checks and counter snapshots are
   present. For restart stress, the recorded cycle count is exact, one PID is retained, final
   generation equals initial generation plus the requested count, route-damage full-rebuild started
   and succeeded deltas equal that count, failed full rebuilds remain at baseline, and ordinary
   ResetNetwork counters do not advance. For network reset, the witness count is exactly 15,
   the exact-test count is 16, the baseline and summary contain the same 8-filter WFP identity, and
   `network-reset-cycles.jsonl` passes exact row/property/value/hash/size/sample readback for the
   requested 10/100/1000 cycles.
5. `cleanup.status` is `pass`; `processes`, `adapters`, `sibling_dll`, and `work_directory` are all
   zero; `cleanup_failure_type` and top-level `failure` are `null`.
6. The command exits zero and emits the terminal marker
   `m17_windows_tun status=PASS ... cleanup=PASS ...`. The host runner's external cleanup also exits
   zero, and `external-cleanup.json` has the exact run token/identity hash with every residue count
   zero. JSON marked pass is not sufficient if either cleanup path fails.

A missing or oversized result, missing logs, a hash mismatch, a noncanonical ledger, incomplete
witnesses, an unexpected exact-test count, residue, timeout, or absent terminal marker is a failed
qualification. Do not infer a pass from partial live traffic or a green step that lacks the complete
artifact set.

The separate `fuzz-smoke` run must preserve `fuzz-smoke.stdout.log`, `fuzz-smoke.stderr.log`,
`fuzz-smoke-result.json`, `guest-run.json`, `staged-input.json`, and `host-orchestration.json`. It must
not fabricate M17 contract/result/cleanup artifacts. Accept it only when the staged smoke executable
hash and size match all three wrapper layers, the candidate and staging-manifest hashes match, exit
is zero, stderr is empty, packet/UDP-reset/config-legacy/strict-route seed counts are exactly
4/3/8/8, and stdout has exactly one line:
`TUN state smoke corpora: 4 packet, 3 UDP reset, 8 config legacy, and 8 strict-route seeds passed`.

The separate hard-kill run must preserve `identity-ledger.json`, `controller.stdout.log`,
`controller.stderr.log`, `hard-kill-evidence.jsonl`, `hard-kill-result.json`, `cleanup.stdout.log`,
`cleanup.stderr.log`, and `hard-kill-cleanup.json`. It does not require and must not fabricate
`m17-contract.json`, `m17-result.json`, or `external-cleanup.json`. Accept hard-kill only when all of
the following are true:

The eight guest files are exported under `<EvidenceDirectory>\guest\export`. The host evidence root
also contains the byte-identical input ledger and topology manifest, the staged-input manifest, and
`host-orchestration.json`. A failed run may publish it with `status: fail` for diagnosis; `status:
pass` is valid only after the exact checkpoint is restored and the approved VM is confirmed `Off`.
`-DescribeContract` reports
`ferrum2.windows-tun.hard-kill-static-contract.v2`; the staged input, guest bootstrap, and host-run
schemas are respectively `ferrum2.windows-tun.hard-kill-staged-input.v2`,
`ferrum2.windows-tun.hard-kill-guest-bootstrap.v2`, and
`ferrum2.windows-tun.hard-kill-hyperv-host-run.v2`; it also reports evidence-row schema `2` and
exactly two strict-route cases.

1. Controller exit is zero and stdout contains exactly one full
   `m16_windows_hard_kill status=PASS cases=3/3 ... strict_route_wfp=ABSENT cleanup=PASS ...`
   terminal line. Its guest build,
   run token, candidate SHA, controller/probe SHA, and identity SHA must exactly match the ledger and
   current candidate.
2. `hard-kill-evidence.jsonl` is the exact controller sidecar and has exactly three ordered rows:
   `hard-kill-auto-route`, `hard-kill-auto-dns`, and `hard-kill-mixed`. Every row has schema integer
   `2`, a round-trip UTC timestamp, and the closed data fields `process`, `adapter`, `addresses`,
   `routes`, `dns`, and `strict_route_wfp`; the first five are string `absent`. The route-only WFP
    object is exactly `{ applicable: false }`. Each DNS WFP object contains only `applicable: true`,
    a `before_kill` identity, and an `after_kill` absence object. `before_kill` binds the fixed session
    and sublayer keys, nonzero UInt32 owner PID, the exact managed-adapter nonzero UInt64 interface
    LUID, the AppId SHA-256 independently derived from the exact staged client executable, eight
    fixed-key/nonzero-UInt64-ID pairs, and a recomputable lowercase SHA-256. `after_kill` records
    session, sublayer, and filters as `absent`.
3. `hard-kill-result.json` has schema `ferrum2.windows-tun.hard-kill-result.v2`, status `pass`, mode
   `hard-kill`, the exact token plus identity, candidate, client, server, and controller hashes,
   exact topology manifest/switch/listener identities, exact guest support path, integer `cases: 3`,
   five true residue-absence booleans, `strict_route_cases: 2`, true
   `strict_route_wfp_identity_verified` and `strict_route_wfp_absent`, `inner_cleanup: pass`, and
   hashes matching the three captured controller files.
4. The artifact-less outer cleanup exits zero. `hard-kill-cleanup.json` has schema
   `ferrum2.windows-tun.hard-kill-cleanup.v2`, status `pass`, source mode `hard-kill`, the exact run
   token and available identity hash, and the recorded qualification outcome. Its process, adapter,
   target-address, target-route, DNS, sibling-DLL, work-directory, mutation-journal, firewall-rule,
   and identity-journal counts are integer zero.
5. Both wrapper JSON files pass their immediate closed-property, JSON-type, timestamp, hash, and
   exact-file readback, and the artifact upload succeeds even when qualification or cleanup fails.
6. The host-run result repeats the exact topology and support-listener bindings, reports
   `checkpoint_restored`, `host_tun_unchanged`, and `host_support_unchanged` as true,
   `host_network_mutations` as integer zero, and `final_vm_state` as `Off`.

## Failure handling and cleanup

On any failure, retain the primary worker failure and every supervisor-recovery failure separately;
the combined exception must not let cleanup mask the original cause. Do not reuse the
guest state or run token, and do not rerun merely to replace failed evidence. Run the token-scoped
cleanup once through the repository controller. Export the persistent artifact directory and hash
its contract, result, and logs before restoring the checkpoint. For M17, `m17-result.json` should report
`status: fail` and a bounded failure record when preflight reached artifact initialization; if it is
absent, record that as an additional failure. For hard-kill, retain the captured controller and
cleanup logs plus any copied ledger, sidecar, or wrapper result. The supervisor removes its exact
deterministic pending manifest and invalidates any PASS or malformed final manifest before returning
failure; a closed schema/token/VM-bound `status: fail` manifest may remain. A passing
`hard-kill-cleanup.json`
proves only that the failed run was reaped; its `qualification_outcome` cannot promote the run to a
qualification pass.

If repository cleanup fails, do not attempt broad manual network cleanup. Stop further testing,
export whatever evidence is safely readable, shut down or turn off only the exact approved VM, and
restore the approved checkpoint. A cleanup failure can never be waived into a pass.

## Mandatory final checkpoint restore

This sequence is mandatory after every local M17, fuzz-smoke, or hard-kill invocation and after every
failed or abandoned run. The supervisor performs it automatically for an observed worker outcome;
after supervisor termination or host restart, the operator must perform it before starting another
qualification:

1. Export all guest artifacts and the identity ledger to the evidence store; compute and record
   their hashes outside the guest.
2. Reap the hidden worker Job first. Use a bounded child process to resolve only the captured VM GUID,
   turn it off with `Stop-VM -TurnOff -Force`, and prove `Off`. A name mismatch is reported after the
   exact GUID has been made safe; it never causes selection of a substitute VM.
3. Only while the VM is proven `Off`, re-resolve the captured checkpoint GUID and cross-check the VM
   name, checkpoint name, and captured source-parent GUID. Restore only that checkpoint. Any mismatch
   leaves the exact VM `Off` and fails recovery.
4. Run the bounded exact-GUID stop once more, read back the exact VM ID/name/state, and leave it
   `Off`. Do not restart it for post-run
   inspection.

The user-facing process never performs an unbounded in-process `Remove-PSSession`, `Stop-VM`, or
`Restore-VMSnapshot` sequence after entering the VM-active phase. Synchronous PowerShell Direct is
confined to the worker; the supervisor's independently captured authority and bounded child helpers
remain available if that worker hangs. They are not available after the supervisor itself has exited,
so unexpected supervisor termination requires a fresh, exact-ID-bounded recovery process rather than
a qualification retry.

Record the restore completion time, exact VM/checkpoint IDs, final `Off` state, candidate SHA,
identity-ledger SHA-256, and exported artifact hashes in the external qualification record. Only a
complete twelve-invocation evidence set—ten M17 profiles, fuzz smoke, and hard-kill—together with
successful applicable cleanup and this final restore satisfies the
Windows qualification and lifecycle-stress portion of the managed-TUN Definition of Done.
