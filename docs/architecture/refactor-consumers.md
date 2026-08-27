# Refactor Consumer Ledger

Use this ledger before renaming a crate, package, target, test, controller or staged artifact. All
listed consumers are updated atomically; a repository-wide search and the listed readbacks must be
clean before merge.

| Identity | Canonical producer | Known consumers | Required readback |
|---|---|---|---|
| `ferrum2-platform-windows` package/path | root workspace and crate manifest | root manifests/lock, bins/TUN manifests, fuzz manifest/lock, m0 workspace policy, all root workflows, M17 runbook | no old Cargo identity; root metadata; both locks; Windows no-run |
| `ferrum2_platform_windows` lib target | Windows platform Cargo target | `run_windows_tun_hyperv.ps1` test-artifact discovery | host build resolves exactly one lib test artifact |
| `ferrum2-platform-windows-tests.exe` | Hyper-V host staging | staged-input manifest, guest controller, identity ledger `test_binaries.wintun`, exact-test dispatcher | staged hash equals ledger and guest readback |
| Windows platform exact test IDs | `windows::ffi::tests::<owner>::*` and crate-root tests | `qualify_windows_tun.ps1` exact-test table; host runner expected-test list | every listed exact test executes once in approved guest and witness count is unchanged |
| client/TUN exact test binaries | Cargo test JSON artifact discovery | Hyper-V host staging, controller, ledger fields `client` and `tun` | package/target/file/hash all agree |
| main/hard qualification entrypoints | main uses `qualify_windows_tun.ps1`; independent hard-kill uses `qualify_windows_tun_hard_kill.ps1` | their respective host runner, staged-input `files.controller`, ledger `probe_sha256`, contract/result `controller_sha256` and runbook command | each flow stages and verifies its own entry SHA; hard-kill never calls the main entrypoint |
| closed qualification-controller bundles | main source manifest is the exact 33-file closure; hard source manifest is the exact 20-file closure: hard entrypoint, 9 shared `Guest.*` primitives, 5 `Hard.*` owners and 5 Common/Evidence files | main, hard-kill and performance staged input; identity ledger schema 3; M17/hard-kill/guest/host evidence; runbook | schema `ferrum2.qualification-controller-bundle.v1`; canonical path/byte/hash rows and `controller_bundle_sha256` agree at every layer; the hard map contains zero `Main.*` sources and no GuestController module |
| main/hard host source-bundle manifests | `tests/platform/{main,hard}-source-bundle.json` | runner bootstrap readback and `test_qualification_modules.ps1` | every listed path/byte/hash and bundle root matches the checked-in source before any host transaction begins |
| 11 main Hyper-V profiles | main host runner `ValidateSet` | runbook required-mode table and guest dispatch | exact profile set and reset/restart cycle counts |
| independent hard-kill | hard-kill host runner + guest wrapper | static/staged/result/bootstrap/host-run v3 schemas and cleanup v2 | remains separate from main Profile dispatcher |
| topology runtime/provisioning helpers | `tools/windows-tun/windows_tun_hyperv_support_topology_*` | ordinary M17 runner, hard-kill runner, Windows performance runner, provision/inspect scripts | literal paths, hashes, LibraryOnly exports and staged probe identities |
| `python -B -m tools.performance_candidate` | Python controller CLI | performance workflow, Windows performance runner, tests | The package entrypoint is unique; JSONL/schema stays unchanged unless separately versioned |
| shared `resolver.test` TLS fixture set | `tests/fixtures/dns-tls` README + architecture policy hashes | DNS interop root/runtime owner, RuleSet HTTPS contract, m0 external DNS qualification | exact byte length/SHA-256 and every canonical path pass `workspace_policy`; DNS interop and RuleSet HTTPS tests compile and run |
| M4 JSON/JSONL schemas | `ferrum2-m4-qualification`; current profile-trial schema v4 | performance controller, workflows, policy/tests | producer self-check, consumer tests, exact schema/version |
| Linux candidate six-pair schemas | `python -B -m tools.performance_candidate`; plan v6, profile trial v4, summary v7, schedule `abba-six-pairs`, exactly 6 pairs | manual performance workflow, policy and owner-split tests | workflow input permits only 6; producer/consumer schema constants and all 12 parent/candidate trials agree |
| Windows TUN candidate six-pair schemas | performance candidate plan v4, trial v5, summary/calibration v4, policy v4, schedule `abba-six-pairs`, exactly 6 pairs | local performance runner, collector, network model and policy/tests | canonical runtime `controller_bundle_sha256` agrees from plan through raw trial, reducer and calibration applicability; no live run here; 12 member observations per metric agree |
| Rule performance schemas | `python -B -m tools.performance_rule` + rule qualification; runner v1, current control v6 and reviewed calibration v2 | owner-split hermetic tests, current six-pair synthetic contract, test-owned historical v2-v4 archive verifier | ordinary gate discovers `test_*.py`; release evidence is explicit qualification and historical formats are not production inputs |
| CI Git comparison range | `tools/ci/git_changes.py` typed event/base/head contract | `tools/ci/{change_contract,fuzz_contract}.py` and their root workflows | pull requests use merge-base diff, pushes use direct range, renames expand to old-path deletion plus new-path addition, paths are NUL-delimited, and missing/unknown/failed comparisons return an explicit fail-closed result |
| fuzz owner-impact paths | `workspace_policy/architecture.toml:[fuzz_impact]` | refactor review and `tools/ci/fuzz_contract.py` | include full TUN and Windows source trees, all platform controller sources, the fuzz and shared Git contract controllers, workflow/workspace, exact transitive local path dependencies, root manifest/lock and vendor; one controller emits the validated impact, target-matrix, and per-target budget while the workflow always emits its required context |
| root `Cargo.lock` | root workspace resolution | ordinary CI, release/profile builds, vendor policy | `--locked`; local patched crypto has no registry source/checksum |
| fuzz `Cargo.lock` | standalone fuzz workspace | deterministic/libFuzzer build, hosted one-hour campaign, and guest smoke | `--locked`; offline metadata, nightly, and local vendor patch agree |
| Windows/Unix Python command | platform command environment | AGENTS, ordinary workflow, developer instructions | Windows uses `python`; Unix uses `python3`; same unittest selection |
| runbook commands/paths | `docs/windows-tun-m17-qualification.md` | operator procedure | docs link/path command checker after every rename/split |
| branch protection contexts | external repository settings | merge policy | main `m3 / required` and fuzz `tun-fuzz-static / required` must both be required; external settings readback remains mandatory and currently unknown |

## Exact Windows platform live-test cohort

The current controller/host contract names, at minimum, the following identifiers. This list is an
identity migration guard, not permission to execute them on an ordinary host.

```text
windows::ffi::tests::underlay::dual_stack_target_binding_selects_actual_target_and_rejects_tun
windows::ffi::tests::underlay::target_binding_excludes_tun_and_orders_prefix_then_effective_metric
windows::ffi::tests::notification::network_change_notifications_cover_each_callback_and_runtime_owned_events
windows::ffi::tests::managed_routes::managed_route_cleanup_preserves_replacements_and_audits_every_delete
windows::ffi::tests::managed_routes::managed_address_readback_and_cleanup_are_exact_and_foreign_safe
windows::ffi::tests::session::dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit
windows::ffi::tests::strict_route::managed_state_health_reports_owned_route_dns_and_strict_route_damage
windows::ffi::tests::strict_route::strict_route_health_reads_every_exact_filter_id_and_rejects_damage
windows::ffi::tests::underlay::network_change_revalidates_underlay_and_owned_routes_before_shutdown
windows::ffi::tests::catalog::windows_catalog_is_family_aware_and_marks_the_exact_managed_tun
windows::ffi::tests::catalog::resolved_socket_binding_applies_interface_then_family_source
windows::ffi::tests::dns::managed_dns_snapshots_reads_back_and_conditionally_restores
tests::operation_error_kinds_are_closed_and_redacted
windows::ffi::tests::session::receive_null_distinguishes_empty_recoverable_eof_and_corruption
windows::ffi::tests::session::send_allocation_failure_distinguishes_ring_full_from_fatal_errors
```
