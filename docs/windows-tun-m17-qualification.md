# Windows TUN qualification

This document defines the privileged correctness qualification for Ferrum2's Windows TUN path.
It is deliberately separate from portable crate tests and Windows TUN performance measurement.

## Scope

The qualification proves behavior that requires a real Windows guest, Wintun, and live Windows
network state:

- adapter creation, identity, and teardown;
- managed addresses, routes, DNS, and strict-route WFP state;
- network-reset and restart endurance;
- live IPv4/IPv6 fragment handling and synthetic DNS;
- live UDP filtering, association, capacity, and protocol traffic;
- scheduler and Wintun egress-pressure accounting;
- external cleanup and checkpoint restoration.

It does not execute Rust unit tests, deterministic fuzz smoke, benchmark trials, ABBA comparison,
or performance policy. Pure Rust tests and deterministic smoke run in ordinary CI. Performance has
its own entry point and evidence contract under `tools/windows-tun/performance`.

The independent hard-kill gate remains owned by
`tests/platform/run_windows_tun_hard_kill_hyperv.ps1`; it is not a mode of the main controller.

## Approved entry point and suites

Only `tests/platform/run_windows_tun_hyperv.ps1` may start a main qualification campaign. Its public
interface accepts one of three closed suites; `-Profile` is an internal worker parameter and is not
an operator interface.

| Suite | Profiles, in fixed order | Purpose |
|---|---|---|
| `Core` | `fragments`, `dual-stack-dns`, `udp-policy`, `scheduler-ring-full` | live functional correctness |
| `Endurance` | `network-reset`, `restart-stress` | 1,000-cycle endurance with intermediate milestones |
| `Release` | all six profiles in Core order followed by Endurance order | complete release qualification |

The internal closed profile set is:

| Profile | Live qualification |
|---|---|
| `network-reset` | 1,000 lightweight resets with milestones at 10, 100, and 1,000 |
| `restart-stress` | 1,000 route-damage rebuilds with milestones at 10, 100, and 1,000 |
| `fragments` | live large IPv4/IPv6 UDP reassembly and fragmented synthetic DNS |
| `dual-stack-dns` | IPv4-only, IPv6-only, and dual-stack DNS apply/readback/restore |
| `udp-policy` | live ADF/EIF, EIM, capacity, payload, firewall-journal, and v4/v6 behavior |
| `scheduler-ring-full` | live 8/16/64 bursts and closed egress-pressure accounting |

Cleanup is a separate internal entrypoint invoked after the live profile process; it is not a
profile or a branch of the live guest controller. The main guest controller rejects every legacy
M15/M16 profile, `performance`, `hard-kill`, and `fuzz-smoke`.

Example release campaign:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_hyperv.ps1 `
  -Suite Release `
  -CampaignToken release-001 `
  -IdentityLedger C:\evidence\identity-ledger.json `
  -TopologyPlanPath C:\Ferrum2\lab-topology.json `
  -TopologyManifestPath C:\evidence\topology.json `
  -TopologyManifestSha256 <sha256> `
  -SupportTcpPort 18080 `
  -SupportUdpPort 18081 `
  -SupportPid <pid> `
  -SupportOwner <owner> `
  -WintunZip C:\inputs\wintun-0.14.1.zip `
  -EvidenceDirectory C:\evidence\release-001
```

Do not run this command on an ordinary development host. The read-only identity probe has a separate
entrypoint, `tests/platform/probe_windows_tun_hyperv.ps1`.

## Campaign, transaction, and staging contract

The host must:

1. verify the clean candidate, source bundle, VM, checkpoint, topology, support listener, credential,
   Wintun archive, portable PowerShell archive, and runtime libraries;
2. build the client and server once with Rust 1.97.1 and locked dependencies, then write one
   hash-bound candidate artifact manifest reused by every selected profile;
3. run profiles in the suite's fixed order without rebuilding or changing the candidate identity;
4. for each profile, create a fresh supervised worker and a fresh restore/start/stage/execute/cleanup/
   export/stop/restore transaction using the same candidate artifact manifest;
5. verify the VM is Off and the lab topology identity is unchanged between profiles and after the
   campaign; no profile inherits guest state from its predecessor;
6. write `qualification-campaign.json` only after collecting each profile's independently validated
   host evidence.

The guest receives no Git checkout, Cargo installation, Rust test binary, or fuzz executable. The
client and server hashes must match the identity ledger and staged-input manifest.

Shared VM, bundle, topology, and staging primitives come from `Ferrum2.WindowsTun.Lab`.
Qualification-specific file maps and evidence policy remain in `Ferrum2.Qualification.Evidence`.
The topology plan and generated manifest use `lab_checkpoint` exclusively; no compatibility alias is
accepted.

The neutral runtime controller-bundle schema is
`ferrum2.windows-tun-controller-bundle.v1`. The main runtime closure contains exactly 28 files and
the independent hard-kill runtime closure contains exactly 21. Their host source closures contain
exactly 33 and 25 files respectively. Each source manifest hashes every canonical repository path,
includes all three private Lab module owners, and cannot be substituted for the other.

## Main evidence schemas

The main controller writes:

- `m17-contract.json`, schema `ferrum2.windows-tun.m17-contract.v4`;
- `m17-result.json`, schema `ferrum2.windows-tun.m17-result.v4`;
- `external-cleanup.json`, schema `ferrum2.windows-tun.m17-external-cleanup.v1`;
- `network-reset-cycles.jsonl` for `network-reset`;
- `guest-run.json`, schema `ferrum2.windows-tun.hyperv-guest-run.v6`;
- `staged-input.json`, schema `ferrum2.windows-tun.hyperv-staged-input.v6`;
- `host-orchestration.json`, schema `ferrum2.windows-tun.hyperv-host-run.v7`;
- `qualification-campaign.json`, schema `ferrum2.windows-tun.qualification-campaign.v1`.

The shared identity ledger uses schema `4`. It binds the candidate commit, controller entrypoint and
bundle root, built client/server identities, topology manifest, VM, and `lab_checkpoint`. Every
profile must read the same ledger and candidate artifact manifest; a mismatch invalidates the whole
campaign.

The contract and result contain `cycle_limit` and `release_milestones`. For `network-reset` and
`restart-stress`, these are exactly `1000` and `[10, 100, 1000]`. Other profiles use a null limit and
an empty milestone list. There are no `test_binaries`, `deterministic_tests`, or fuzz fields.

Each endurance milestone is a `live_checks` row named
`network-reset-milestone-0010`, `network-reset-milestone-0100`,
`network-reset-milestone-1000`, or the corresponding `restart-stress-*` name. A release result is
valid only when all three milestone rows report `pass`.

## Live witness contract

Only witnesses established by the live product or live platform are accepted. Unit-test-derived
witnesses are forbidden.

| Profile | Required live witnesses |
|---|---:|
| `network-reset` | 6 |
| `restart-stress` | 3 |
| `fragments` | 2 |
| `dual-stack-dns` | 5 |
| `udp-policy` | 12 |
| `scheduler-ring-full` | 2 |

The controller fails if a witness is missing, duplicated, outside the selected profile contract, or has
non-live provenance.

For network reset, `network-reset-cycles.jsonl` contains exactly 1,000 LF-terminated rows. The host
validates every row and the final hash, size, generation, reset, managed-plane, and sampled WFP
identity accounting.

## Performance separation

Windows TUN performance is not qualification evidence. Its canonical runner is
`tools/windows-tun/performance/run_windows_tun_performance_hyperv.ps1`. Performance owns scenarios,
trial ordering, collectors, calibration, ABBA comparison, and thresholds. It may reuse only neutral
Lab mechanics; it must not import qualification profiles or turn correctness evidence into a
performance verdict.

The performance source manifest is an independent closed 38-source identity: three scripts under
`tools/windows-tun/performance`, 25 `Ferrum2.Performance` owners, the six-file
`Ferrum2.WindowsTun.Lab` module, and four Lab helpers that the runner executes directly: the guest
path probe, host path helper, topology read-only owner, and topology runtime. The manifest hash-binds
all four helpers. The performance closure contains no `Ferrum2.Qualification.Evidence` or
`Ferrum2.Qualification.HostHyperV` source.

Likewise, diagnostic performance runs must identify themselves as non-qualifying and cannot satisfy
this gate.

## Local validation

Ordinary hosts may run only static validation:

```powershell
pwsh -NoProfile -File tests/platform/test_qualification_modules.ps1
pwsh -NoProfile -File tests/platform/test_windows_tun_hyperv_static_contract.ps1
```

Parse changed scripts and run `Invoke-ScriptAnalyzer` without starting Hyper-V or touching live TUN
state. The approved guest procedure is required for a selected public suite and the separate
hard-kill gate. The hard-kill static contract, staged input, and host-run schemas are all version 4;
hard-kill remains outside the main campaign.

## Acceptance state

Code and static contracts may be accepted independently, but release qualification remains
`WINDOWS_EVIDENCE_IN_PROGRESS` until one complete `Release` campaign and the independent hard-kill
gate have fresh, identity-bound evidence for the same candidate commit.
