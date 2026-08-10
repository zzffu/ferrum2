---
id: M15-T06
milestone: M15
status: done
depends_on:
  - M15-T05
owns:
  - .github/workflows/m0.yml
  - tests/m0-harness/**
  - tests/platform/qualify_windows_tun.ps1
  - docs/ci-status.md
---

# M15-T06 — Close integrated Windows TUN evidence

## Outcome

Close the completed data plane's independent security、failure、lifecycle、platform and performance evidence
using the existing harness/workflow and one Windows controller。Make privileged functional Windows TUN a
required aggregate result and add one independent manual Windows TUN performance/resource result without
changing existing Linux/Windows/GNU/musl、interop or TUN-absent gates。

## Acceptance

- [x] Artifact acquisition、hash/signature/license/PE/export checks，unique names/prefixes，narrow controller-
      owned routes and `always` cleanup are deterministic and bind one exact candidate SHA。
- [x] Every prepare position、later-root failure、runtime device/thread failure、panic、grace、force、cleanup
      conflict and 100+ repeated lifecycle path proves exact owners and adapter/name/route rebind。
- [x] Architecture/workspace policy guards dependency directions、exact identities/features/MSRV、narrow
      unsafe exception、pointer lifetime、one stack owner、one policy/DNS/SIP022 path and the absence of
      product route/DNS/WFP calls；each has a mutation-sensitive oracle。
- [x] Real-process IPv4/IPv6 TCP/UDP route/chain/selector/sniff/DNS/reject/failure/saturation rows and
      TUN-absent M0～M14 rows pass from fresh binaries with bounded output and secret/destination exclusion。
- [x] Required `windows-tun-e2e` is integrated into the existing aggregate without suppressing quality、
      footprint、MSRV、platform or interop results。It prints the exact `profile=full functional=16/16
      cycles=100/100 cleanup=PASS` marker bound to GitHub SHA/run/attempt only after cleanup。
- [x] Independent manual Windows TUN performance/resource records one TCP and one UDP witness、raw RX/TX、
      CPU/RSS/handles/threads/queues、adapter churn、grace/force drain and cleanup on the exact SHA；it makes
      no threshold or improvement claim，and prints the exact `windows-tun-performance` marker from
      TEST-0016 only after cleanup。
- [x] Product paths are not owned by default。Any discovered product defect requires an explicit narrow
      ownership amendment、descendant repair and fresh focused/full review；evidence code cannot hide a fix。

## Validation

```powershell
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
rustc +1.97.1 --version --verbose
cargo +1.97.1 check --workspace --all-targets --locked
pwsh -NoProfile -File tests/platform/qualify_windows_tun.ps1 -Mode full # local diagnostic only
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: `7ba6268ffa3c5ecc7ba2b91e3ebcae8f596ecbb9` / tree
  `72a3cfb5c881a35b1416cbf9ffea593973cc3570` / parent
  `b04432708f2229562fcb2e4d47f2bfdbfb8daec3`；the isolated workflow commit is
  `4ff38b6d6f0ef07aefa5905b2f56324adcbeec7d`。
- Review: fresh Architect and QA both returned `PASS_WITH_NOTES` after exact-candidate VM full and
  performance runs，with zero blocker、major or minor finding。Their hosted-evidence reservation is closed
  by the exact runs below；performance values remain diagnostic only，and `queues=bounded` is a configured-
  bounds witness rather than measured internal queue depth。
- Notes: serial local architecture `19/19`、workspace policy `25/25`、config CLI `7/7`、format、strict
  Clippy、workspace all-features、ignored 100+ lifecycle、docs、Rust 1.97.1 and diff gates passed。Fresh
  isolated VM full and performance runs emitted the exact `16/16 + 100/100` and `2/2` markers with zero
  guest/host residue。Automatic push run
  [`31368732658/1`](https://github.com/zzffu/ferrum2/actions/runs/31368732658) passed every required job and
  foundation `4/4`；authorized full run
  [`31368750439/1`](https://github.com/zzffu/ferrum2/actions/runs/31368750439) passed all jobs and emitted
  `profile=full functional=16/16 cycles=100/100 cleanup=PASS`；authorized performance run
  [`31368752781/1`](https://github.com/zzffu/ferrum2/actions/runs/31368752781) passed all jobs and emitted
  `witnesses=2/2 cleanup=PASS` plus the closed resource row，all on the exact SHA and attempt 1。Footprint
  integrity and ratio passed；numeric `REVIEW_REQUIRED` `+475/+0/+0` is accepted as distinct full/cycle/
  performance and mutation evidence in the existing harness。No rerun、force-push、PR、tag、package、release
  or publication occurred。

## Rollback / risk

Workflow/controller/tool changes revert independently of product capability。Principal risks are privileged
runner unavailability、cleanup touching non-owned host state、evidence from different SHAs、a false-green
controller or turning a diagnostic throughput value into a release claim。A direct hosted capability failure
is recorded and blocks；Hyper-V/self-hosted fallback needs a new approved control amendment。
