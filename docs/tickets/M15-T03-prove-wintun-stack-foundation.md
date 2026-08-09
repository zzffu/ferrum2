---
id: M15-T03
milestone: M15
status: done
depends_on:
  - M15-T02
owns:
  - .github/workflows/m0.yml
  - Cargo.toml
  - Cargo.lock
  - crates/ferrum2-config/Cargo.toml
  - crates/ferrum2-config/src/**
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-observability/src/**
  - crates/ferrum2-observability/tests/**
  - crates/ferrum2-wintun/**
  - crates/ferrum2-tun/**
  - crates/ferrum2-runtime/src/lib.rs
  - crates/ferrum2-runtime/src/process.rs
  - crates/ferrum2-runtime/tests/lifecycle.rs
  - crates/ferrum2-runtime/tests/shutdown.rs
  - bins/ferrum2-client/Cargo.toml
  - bins/ferrum2-client/src/main.rs
  - bins/ferrum2-client/src/cli.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/tun.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - tests/platform/qualify_windows_tun.ps1
---

# M15-T03 — Prove the privileged Wintun-to-stack foundation

## Outcome

Deliver the first real vertical risk slice：a schema-v2 TUN-only or coexistence config validates offline，
then one required process root starts the final owner thread；that thread securely loads the exact Wintun DLL，
creates/configures a new dual-stack adapter，starts its session to bring media up，waits both non-optimistic
DAD rows to reach exact Preferred，constructs the bounded smoltcp stack，accepts a
controller-routed valid TCP/UDP IP packet and drops it deterministically before policy，then rolls every owned
resource back before exit/join。This ticket atomically activates the exact dependencies、Rust 1.97.1
workspace/CI MSRV and private memory-device evidence in the same slice；it does not yet open egress。

## Acceptance

- [x] Exact target-specific `windows-sys 0.61.2` reuses the lock identity with SPEC-0016's literal direct-edge
      eight features/default-off declaration and no delta outside their Cargo feature closure；exact no-default
      `smoltcp 0.13.1` is the sole lock identity with the literal ten-feature array，including Reno、two
      addresses/routes and four assembler segments，while `auto-icmp-echo-reply` remains absent。
- [x] Workspace `rust-version`、existing selected toolchain、all workflow MSRV selectors and workspace-policy
      assertions are exactly Rust `1.97.1`；no residual M15 `1.88.0`/`1.91` or floating channel remains，and
      all non-Windows targets compile without loading Wintun。
- [x] `ferrum2-wintun` is the only documented/source-guarded unsafe exception and exposes safe RAII
      operations that cannot leak a packet pointer or close the session read event incorrectly。
- [x] `ferrum2-tun` exposes only a flow-level root boundary；its private memory Adapter proves all packet、
      queue、generation、memory and lifecycle invariants without a public test factory。
- [x] Schema-v2 `[tun]` supports TUN-only、coexistence、static/routed identity and complete bounds；v1/server/
      unsupported rule capability/unknown fields fail closed；no dummy SOCKS listener is created。
- [x] Every field boundary and checked memory term matches SPEC-0016；the default is exactly `53,995,616`
      bytes，accepted plans are at most `256 MiB`，and no queue/socket/staging/hidden pool escapes accounting。
- [x] `--check-config` invokes no DLL/device/admin/thread/OS seam。Unsupported compile target is reported by a
      pure pre-success gate；OS/DLL/ABI/admin/driver failures occur during prepare before activation。
- [x] Prepare first starts the final owner thread；that thread alone performs and reverses every DLL/adapter/
      per-family-MTU/address/session/DAD/smoltcp step，and shutdown joins it only after thread-owned cleanup。
      Session start is only the Wintun media-liveness prerequisite；it precedes DAD polling but no RX/TX、
      stack polling or admission，and the creation rows do not request optimistic DAD。Non-blocking activate
      fits the existing `ProcessRoot`/`ProcessSupervisor` unchanged；only naturally reached exact
      `IpDadStatePreferred` is ready，and every setup/later-root failure leaves exact baseline。
- [x] Product contains no explicit route/DNS/WFP API；privileged before/ready/after snapshots distinguish
      expected address-derived system rows from controller-owned routes and prove neither leaks。
- [x] One shared ingress/egress validator enforces SPEC-0016's exact IPv4 IHL-5 and IPv6 direct-6/17 policy；
      every listed extension/truncation、fragment、checksum and length mutation fails before state/TX。
      Exactly two smoltcp internal routes and the eight-packet work quantum are independently proven。
- [x] Direct ephemeral Windows runner smoke is attempted before any Hyper-V plan；artifact provenance、
      always-run cleanup、adapter absence and exact name rebind pass。Hosted job `windows-tun-e2e` emits the
      exact `profile=foundation foundation=4/4 cleanup=PASS` marker bound to SHA/run/attempt；a local controller
      invocation alone is diagnostic and cannot satisfy this row。

## Validation

```powershell
cargo test -p ferrum2-wintun --locked
cargo test -p ferrum2-tun --locked
cargo test -p ferrum2-config --test config_contract --locked tun_
cargo test -p ferrum2-m0-harness --test config_cli --locked tun_
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo tree -p ferrum2-tun -e features --target x86_64-pc-windows-msvc --locked
cargo tree -i smoltcp@0.13.1 -e features --locked
cargo tree -i windows-sys@0.61.2 -e features --target x86_64-pc-windows-msvc --locked
rustc +1.97.1 --version --verbose
cargo +1.97.1 check --workspace --all-targets --locked
cargo check --workspace --all-targets --target x86_64-pc-windows-msvc --locked
pwsh -NoProfile -File tests/platform/qualify_windows_tun.ps1 -Mode lifecycle # local diagnostic only
cargo test --workspace --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: `2eb6db6a200c374ee2765d200413b3497a69694b`；tree
  `17377e4b8eed75c6cb11bb7e47b4fec26aa2f43f`；parent
  `019bbf67398d1de96248d903a72aa4b2ab7b2ded`。
- Review: final Architect and QA both `PASS_WITH_NOTES`；all `ARCH-001..004` and `QA-001..005` are closed
  with zero blocker/major/minor。After the first targeted QA remained blocked，two independent
  `gpt-5.6-sol`/`xhigh` read-only diagnoses agreed on the private-transaction repair that became this exact
  commit。
- Footprint: integrity and ratio `PASS`；code/tests `27907/47322`，ratio `1.695704`；case/support/fixture
  `41573/5152/597`，full-range delta `+2310/+0/+0`。Architect and QA accept numeric `REVIEW_REQUIRED`：the
  growth is distinct failure-position、rollback、DAD、packet、config and production-mutation evidence with no
  new support、fixture、public factory、backend or harness。
- Notes: local focused、Rust 1.97.1、Windows target、Clippy、workspace and privileged lifecycle gates passed。
  Exact hosted run [`31304175220/1`](https://github.com/zzffu/ferrum2/actions/runs/31304175220) passed quality、
  footprint、MSRV、interop、three platforms、`windows-tun-e2e` and qualification；job `93221731378` emitted
  `profile=foundation foundation=4/4 cleanup=PASS` bound to the exact SHA/run/attempt。Integration first found
  a stale pre-T03 client binary；the required workspace-bin build followed by the unchanged failing command
  and full workspace gate passed。

## Rollback / risk

Feature removal and dependency-edge reversion restore M14 behavior；no schema-v2 document without `[tun]`
changes meaning。Highest risks are loader/ABI correctness、narrow unsafe containment、DAD readiness、silent
adapter-removal failure、MTU/address rollback and a hosted runner that cannot load Wintun。Direct evidence
closed the F05 ordering erratum：pre-session media is disconnected and cannot complete DAD，so session start
must precede non-optimistic DAD polling without becoming readiness。A failed direct
probe blocks the ticket and supplies evidence for a separately approved Hyper-V/self-hosted fallback；it is
not waived。
