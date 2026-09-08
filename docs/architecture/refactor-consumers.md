# Refactor Consumer Ledger

Use this ledger before renaming a crate, package, target, test, controller or staged artifact. All
listed consumers are updated atomically; a repository-wide search and the listed readbacks must be
clean before merge.

Architecture policy constrains ownership and execution rather than incidental source layout:

- Internal dependency allowlists are upper bounds: removing an edge is permitted; adding an
  undeclared edge or violating a direct/transitive prohibition is not.
- Shared TLS consumers may move, split or add helpers without registering source filenames.
  Canonical ownership, provenance, byte lengths/SHA-256, forbidden legacy directories and private
  copies remain checked. Rust path operations are token-inspected; comments and arbitrary string
  mentions are not consumer registrations.
- Unsafe tokens and weakening `allow`/`expect`/`warn(unsafe_code)` attributes, including multi-lint
  and `cfg_attr` forms, must stay within reviewed files/subtrees. Allowance counts are not fixed.
- Workflow display-step names and supported equivalent option ordering/spelling are not identities.
  Package/feature/target selection, actual execution, dependency results, budgets and failure
  propagation remain mandatory. Machine job IDs and required status contexts remain fixed.
  Command comparison preserves option-value pairing and positional order; it is not a shell
  interpreter. Reviewed PowerShell provenance and bounded Bash execution envelopes remain narrow
  and reject unsupported control flow rather than accepting matching substrings.

| Identity | Canonical producer | Known consumers | Required readback |
|---|---|---|---|
| `ferrum2-platform-windows` package/path | root workspace and crate manifest | root manifests/lock, bins/TUN manifests, fuzz manifest/lock, m0 workspace policy, all root workflows, host qualification runbook | no old Cargo identity; root metadata; both locks; Windows no-run |
| `ferrum2_platform_windows` lib target | Windows platform Cargo target | hosted Windows compile/test gate | default tests remain unprivileged; no live-backend test-artifact discovery |
| Windows TUN correctness entrypoint | `tests/platform/run_windows_tun_qualification_host.ps1` | operator runbook, static contract, worker supervisor, final verdict | public interface remains PlanOnly/RecoveryOnly/one acknowledged run; no suite, profile, guest, or alternate entrypoint |
| qualification source closure | `tools/powershell/Ferrum2.Qualification.Host/bundle.json` | runner bootstrap, module loader, plan and every evidence file | canonical path/byte/hash rows cover qualification sources and explicit shared private host primitives; complete digest matches before effects |
| fixed host qualification plan | `Ferrum2.Qualification.Host` | static PlanOnly readback and live worker | exact eight checks; 900s outer, 840s worker, 600s build; one exact candidate build; run-owned RFC 2544 `/32` resources only |
| qualification evidence schema family | schema-v1 plan, build, runtime, worker, cleanup, and final documents | operator and final supervisor | candidate/source identities agree; all checks pass; final status is `QUALIFIED`; cleanup counts are zero; elapsed is below 900s |
| TUN benchmark recipe closure | `crates/ferrum2-tun/examples/tun-benchmark.rs` and `src/benchmark{.rs,/owner.rs,/recipe.rs}` | `tun_mock_contract.py`, independently built benchmark members and calibration | exact recipe file hashes, workload identities, scenario units and checked counts; product source may differ but recipe/controller/environment must match |
| `python -B -m tools.performance_candidate` | Python controller CLI | Linux and TUN-only performance evidence/tests | Unique entrypoint; TUN uses calibrate/run/validate with bounded process ownership and no host performance compatibility reader |
| owned subprocess lifetime | `tools/owned_process.py` | CI provisioning, CPU diagnostics, TUN mock execution, Rule runner capture, controller source-identity builders | Windows and Linux offline process contracts; retained Unix leader identity through final signals; exact source closure includes shared owner |
| dashboard command wire contract | `crates/ferrum2-dashboard/src/wire.rs` | client HTTP/controller/domain adapters; `ui/dashboard/scripts/wire.ts`, generated browser declarations and embedded HTML | Rust admission tests, `bun scripts/wire.ts --check`, frontend typecheck/build identity, real authenticated commands and generation conflicts |
| shared `resolver.test` TLS fixture set | `tests/fixtures/dns-tls` README + architecture policy hashes | DNS interop root/runtime owner, RuleSet HTTPS contract, m0 external DNS qualification; source-file inventory is not fixed | canonical ownership, byte length/SHA-256 and absence of private copies pass `workspace_policy`; DNS interop and RuleSet HTTPS tests compile and run |
| M4 JSON/JSONL schemas | `ferrum2-m4-qualification`; current profile-trial schema v4 | performance controller, workflows, policy/tests | producer self-check, consumer tests, exact schema/version |
| Linux candidate six-pair schemas | `python -B -m tools.performance_candidate`; plan v6, profile trial v4, summary v7, schedule `abba-six-pairs`, exactly 6 pairs | manual performance workflow, policy and owner-split tests | workflow input permits only 6; producer/consumer schema constants and all 12 parent/candidate trials agree |
| TUN mock evidence schema | schema-v1 raw trials and A/A or A/B manifest; Quick 3 pairs and Confirm 5 across six scenarios | local controller and strict offline validator | source/binary/controller/recipe/environment identities, complete raw schedule, exact work counts, sampled packet storage and recomputed per-scenario decisions; reviewed calibration digest required for A/B |
| Rule performance schemas | `python -B -m tools.performance_rule` + rule qualification; runner v1, current control v6 and reviewed calibration v2 | owner-split hermetic tests, current six-pair synthetic contract, test-owned historical v2-v4 archive verifier | ordinary gate discovers `test_*.py`; release evidence is explicit qualification and historical formats are not production inputs |
| CI Git comparison range | `tools/ci/git_changes.py` typed event/base/head contract | `tools/ci/{change_contract,fuzz_contract}.py` and their root workflows | pull requests use merge-base diff, pushes use direct range, renames expand to old-path deletion plus new-path addition, paths are NUL-delimited, and missing/unknown/failed comparisons return an explicit fail-closed result |
| fuzz owner-impact paths | `workspace_policy/architecture.toml:[fuzz_impact]` | refactor review and `tools/ci/fuzz_contract.py` | include full TUN and Windows source trees, all platform controller sources, the fuzz and shared Git contract controllers, workflow/workspace, exact transitive local path dependencies, root manifest/lock and vendor; one controller emits the validated impact, target-matrix, and per-target budget while the workflow always emits its required context |
| root `Cargo.lock` | root workspace resolution | ordinary CI, release/profile builds, vendor policy | `--locked`; local patched crypto has no registry source/checksum |
| fuzz `Cargo.lock` | standalone fuzz workspace | deterministic/libFuzzer build and hosted one-hour campaign | `--locked`; offline metadata, nightly, and local vendor patch agree; no privileged-network staging |
| Windows/Unix Python command | platform command environment | AGENTS, ordinary workflow, developer instructions | Windows uses `python`; Unix uses `python3`; same unittest selection |
| runbook commands/paths | `docs/windows-tun-qualification.md` | operator procedure | docs link/path command checker after every rename/split |
| branch protection contexts | external repository settings | merge policy | main `m3 / required` and fuzz `tun-fuzz-static / required` must both be required; external settings readback remains mandatory and currently unknown |
