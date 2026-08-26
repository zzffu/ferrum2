# Gate Ledger

This ledger maps every current gate to its eventual CI owner. A workflow refactor is accepted only
when each row has an explicit readback and the old and new results agree. `Required context` is an
external repository setting; unknown values stay marked as gaps rather than being inferred.

| ID | Current workflow / job / step | Trigger and status | Command or contract | Timeout / privilege | Provider, evidence and cleanup | Target / migration status |
|---|---|---|---|---|---|---|
| G-QUALITY | `m0.yml:quality` named steps | PR, master/integration push; included by `m3 / required` | architecture policy, build/example, fmt, clippy, safe workspace tests, client/TUN/Windows-platform no-run, DNS interop-root, M4 self-check, docs | 60m; ordinary Linux | Ubuntu image/toolchain evidence; no raw artifact | retained as one job to reuse checkout/toolchain/build state |
| G-PY-CANDIDATE | `m0.yml:quality:Test candidate controller` | same | `python3 -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v` | ordinary Linux | Owner-split hermetic unittest discovery; no ignored raw evidence | current named step |
| G-PY-RULE | `m0.yml:quality:Test Rule ordinary controller` | same | `python3 -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v`; runner v1, current control v6 and reviewed-calibration v2 contracts | ordinary Linux | Owner-split hermetic controller tests only; historical v2-v4 are archive-verifier inputs | current named step |
| G-IPV6 | `m0.yml:quality:Prove focused IPv6 UDP real-process path` | PR/push | exact ignored m0 IPv6 UDP process test under a two-minute bound | ordinary hosted Linux | process cleanup asserted by test | current |
| G-WIN | `m0.yml:platform / windows-msvc` | PR/push; included by `m3 / required` | release client/server build, client/TUN/Windows-platform test compile-only, hosted native qualification, qualification PowerShell static contracts, PE/dependency readback, detection probe | 60m; ordinary hosted Windows; no TUN execution | Windows 2022, MSVC and toolchain evidence | current matrix member |
| G-GNU | `m0.yml:platform / linux-gnu` | PR/push; included by `m3 / required` | release build, native qualification, ELF/interpreter/DT_NEEDED/GLIBC readback | 60m; ordinary hosted Linux | Ubuntu 24.04 compiler/linker/glibc evidence | current matrix member |
| G-MUSL | `m0.yml:platform / linux-musl` | PR/push; included by `m3 / required` | exact musl packages, release build, native qualification, no interpreter/DT_NEEDED | 60m; ordinary hosted Linux | pinned apt package versions and linkage output | current matrix member |
| G-INTEROP | `m0.yml:interop` | PR/push; included by `m3 / required` | provision hash/version-bound sing-box, shadowsocks-rust, CoreDNS and BIND; run hosted TCP/UDP/DNS qualification | 60m; ordinary network providers | provider hashes/status; temporary target cleanup must pass | current |
| G-M4 | `m0.yml:performance` | manual `dispatch_target=performance`; not an ordinary PR gate | M4 throughput/resource/DNS-resource qualification | 90m; hosted performance | raw artifact upload; process/evidence/THP cleanup uses `always()` and must pass | manual qualification; current |
| G-FUZZ-DET | `tun-fuzz-deterministic.yml:deterministic-build` | every PR, protected push + manual; included by independent `tun-fuzz-static / required` | nightly fmt/check/test-no-run/smoke build, offline after fetch | 20m; compile-only | independent fuzz lock/nightly; no target execution | retained independently; workflow-level path skipping forbidden |
| G-FUZZ-LIB | `tun-fuzz-deterministic.yml:libfuzzer-build` | same | cargo-fuzz 0.13.2 builds four targets offline | 20m; compile-only | exact cargo-fuzz version; generated-diff readback | retained independently; workflow-level path skipping forbidden |
| G-MAIN-REQUIRED | `m0.yml:required` | every main workflow run | explicitly requires `quality`, aggregate `platform`, and `interop` results to be `success` | 5m; ordinary Linux | no checkout or artifacts | stable main context; external branch-protection readback pending |
| G-FUZZ-REQUIRED | `tun-fuzz-deterministic.yml:required` | every triggered fuzz workflow run | explicitly requires deterministic and libFuzzer build results to be `success` | 5m; ordinary Linux | no checkout or artifacts | stable independent fuzz context; external branch-protection readback pending |
| G-LIFECYCLE | `lifecycle-stress.yml:lifecycle-cycles` | weekly + manual; scheduled | 20 cycles/category and at least 100/binary exact ignored test | 40m; ordinary hosted Linux | exact SHA/clean checkout; test reaps children | current scheduled/manual non-required workflow |
| G-PERF | `performance-candidate.yml:paired-profile` | manual only | correctness builds/tests and the only accepted six-pair `abba-six-pairs` schedule; Linux plan/trial/summary schemas v6/v4/v7 | 180m; performance | raw evidence retained 30 days; worktrees/processes removed in `always()` | manual performance; calibration required after schema/pair identity change |
| G-HV-PROFILES | local `run_windows_tun_hyperv.ps1` | manual approved host; never CI | 11 closed profiles: reset/restart 10/100/1000, fragments, dual-stack DNS, UDP policy, ring full, fuzz smoke | 30m probe / 2h ordinary / 3h bounded outer supervisor; privileged guest only | hash-bound staging/export; cleanup, same checkpoint restore and final Off | approved local only; live pending |
| G-HV-HARDKILL | local `run_windows_tun_hard_kill_hyperv.ps1` | separate manual gate | independently versioned three-case hard-kill qualification | 2h; privileged guest only | independent result/cleanup schemas; final Off | approved local only; live pending |
| G-PS-STATIC | `m0.yml:platform / windows-msvc:Validate Windows qualification static contracts`; local hard-kill `-DescribeContract` | PR/push for module and static-supervisor tests; DescribeContract remains an operator readback | parse/manifest/export/closed schema and failure contracts; no VM/credential access | ordinary Windows | no network mutation | wired without live Hyper-V execution |

## R0 readback rules

- The root ordinary test gate excludes `ferrum2-client`, `ferrum2-tun`, and the Windows platform
  crate, then compiles their test binaries with `--no-run`.
- `qualify_native.py` is workflow-only because it requires GitHub runner identity; it is not a local
  developer command.
- Root CI and fuzz-static expose separate `required` jobs. Branch protection must require both stable
  contexts; because repository settings are external, that readback remains a gap.
- Hosted jobs never execute TUN smoke, libFuzzer targets, Wintun/TUN tests, adapter, route, DNS, WFP,
  checkpoint or Hyper-V operations.
