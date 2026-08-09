---
id: M15-T01
milestone: M15
status: ready
depends_on: []
owns:
  - CONTEXT.md
  - ci/test-budget-baseline.txt
  - docs/adr/ADR-0034-m15-windows-tun-ownership-and-policy-seams.md
  - docs/milestones/M15-windows-wintun-tun-data-plane.md
  - docs/research/M15-wintun-smoltcp-windows-baseline.md
  - docs/roadmap.md
  - docs/specs/SPEC-0016-m15-windows-wintun-tun-data-plane.md
  - docs/test-plans/TEST-0016-m15-windows-wintun-tun-data-plane.md
  - docs/tickets/M15-T*.md
---

# M15-T01 — Freeze Windows TUN contracts and controls

## Outcome

Accept one isolated control-plus-Markdown commit that replaces the external discussion draft with the
repository-native M15 outcome、ADR、spec、test plan and seven-ticket serial DAG，pins the exact planning base，
records dependency/artifact/license dispositions and activates the M15 footprint baseline before product
work。

## Acceptance

- [ ] Qualified M14 product/tree and planning HEAD/tree/parent resolve exactly；their intervening diff has no
      Rust product、test、manifest、lock or workflow change。
- [ ] ADR-0034、SPEC-0016、TEST-0016 and all seven tickets agree on manual-route ownership、schema v2、
      deterministic TUN-last ordinary indexing、TUN-only support、two-module seam、owner-thread setup/cleanup
      before join、bare-header dual-stack TCP/UDP、eager TCP handshake and provisional UDP decision-before-
      mapping commitment。
- [ ] Research records exact Wintun ZIP/DLL hashes、custom license、ABI、secure-load limits、Windows-managed
      route side effects，locked `windows-sys 0.61.2` reuse、owner-selected exact smoltcp `0.13.1` and official
      planning-date latest stable Rust `1.97.1`；SPEC
      freezes all eleven exports、the literal windows-sys direct-edge eight-feature declaration/closure delta、
      exact smoltcp ten-feature array、two internal routes and held non-reparse path hash/load。
- [ ] Every public TUN field has one required/default/range/meaning，the checked memory formula evaluates to
      exact default `53,995,616` bytes，and DAD readiness is exactly `IpDadStatePreferred`。
- [ ] No contract retains schema 3、M15-final Rust 1.88、the nonexistent negative smoltcp feature、the positive
      `auto-icmp-echo-reply` feature、fragment reassembly、the 2-GiB defaults、three preparatory crates、
      blocking activation or product-owned capture routes。Rust 1.91 remains only the recorded dependency
      minimum；the exact M15 target is 1.97.1。
- [ ] Schema-3 footprint control uses exact `bd374c6…` counts `25586/45009`，unchanged thresholds、revision 1
      and TEST-0016 reforecast reference；case/support/fixture baseline is `39260/5152/597`。
- [ ] Current Quick、Rust 1.88 baseline and footprint-integrity gates pass unchanged；an additional exact
      Rust 1.97.1 forward check passes without yet changing product/workflow state。T03 owns the atomic
      workspace/CI/policy MSRV transition；no remote state changes。

## Validation

```powershell
git rev-parse HEAD 'HEAD^{tree}' 'HEAD^'
git diff --name-only bc6963472d9ae8e3c84d82851fd64d78c9f2a65f..HEAD
cargo tree -i windows-sys@0.61.2 -e features --target x86_64-pc-windows-msvc --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --bins --locked
cargo test --workspace --locked
cargo +1.88.0 check --workspace --all-targets --locked
rustc +1.97.1 --version --verbose
cargo +1.97.1 check --workspace --all-targets --locked
git diff --check
```

## Result

- Commit: —
- Review: —
- Notes: plan-only；no remote action authorized。

## Rollback / risk

Rollback restores the M14 footprint control and removes only M15 planning documents。The main risk is
freezing an upstream or host-network assumption not supported by primary evidence；T02/T03 must bind the
accepted exact T01 commit and may not silently widen the contract。
