# TEST-0005 — M4 performance, resource, and v0 preview qualification

- Status: planned
- Milestone: M4
- Spec: `docs/specs/SPEC-0005-m4-performance-resource-preview-qualification.md`
- Baseline: `701925681df78ad83076ed67863bf4fecf46f77c`

## Evidence map

| Requirement | Primary evidence | Command / gate |
|---|---|---|
| M4-MUST-01 identity and cleanup | driver self-check plus `performance` job hosted preflight and negative mutations | T01 focused commands; hosted job |
| M4-MUST-02 throughput | five ferrum2 and five reference release trials on one runner VM | hosted `m4-qualification throughput` |
| M4-MUST-03 10k idle | same-job 10k establishment, 180 samples, six RSS windows, exact drain | hosted `m4-qualification resource` |
| M4-MUST-04 evidence boundary | runner-temp path, redaction, bounded-capture, deletion, and Git-status checks | self-check plus hosted job |
| M4-MUST-05 same-SHA convergence | one authorized GitHub Actions `push` run/attempt | T02 exact-SHA gate |

The new execution seams are the Cargo-managed M4 driver and one `performance` job in
the existing workflow. They reuse the release binaries, SOCKS/metrics mechanics,
stable active gauge, `/proc`, and reference pin. A new workflow, product endpoint,
benchmark dependency, or separate soak harness would duplicate existing evidence
without a distinct failure mode.

## M4-T01 focused validation

```sh
cargo fmt --all -- --check
cargo check -p ferrum2-m0-harness --all-targets --locked
cargo run --release -p ferrum2-m0-harness --bin m4-qualification --locked -- self-check
cargo test -p ferrum2-m0-harness --locked
sh scripts/test-budget.sh ticket --base 701925681df78ad83076ed67863bf4fecf46f77c --candidate <candidate-sha>
git diff --check 701925681df78ad83076ed67863bf4fecf46f77c..<candidate-sha>
```

`self-check` uses a short, small-count profile and deterministic synthetic samples. It
MUST kill mutations for wrong SHA/host/reference, missing samples, changing owner/task
tuples, a sixth RSS window over 105%, incomplete drain, leaked child, and secret output.
It is not M4 qualification evidence.

## Local WSL2 diagnostic

WSL2 is only a short feedback loop for the driver and test code. Its output is not M4
qualification evidence and no local CPU, kernel, memory, or benchmark result is copied
into closeout evidence.

```powershell
wsl.exe -d Debian -- bash -lc '
  set -euo pipefail
  cd /mnt/c/project/ferrum2
  rustc +1.97.1 --version | grep -Fx "rustc 1.97.1 (8bab26f4f 2026-07-14)"
  cargo +1.97.1 run --release -p ferrum2-m0-harness \
    --bin m4-qualification --locked -- self-check
'
```

The normal quick/full and test-budget commands remain required before integration, but
their Windows or WSL2 results are pre-push diagnostics rather than formal M4 evidence.

## Hosted `performance` job

M4-T01 extends `.github/workflows/m0.yml` with job ID/name `performance`,
`runs-on: ubuntu-24.04`, `timeout-minutes: 90`, and no `continue-on-error`, cache,
secret, artifact upload, or cross-job ferrum binary. It runs for `push` and
`workflow_dispatch`, but is skipped for `pull_request`; only a separately authorized
`push` run is eligible for M4 close.

The job checks out the exact current SHA using the existing pinned checkout action and,
before generated writes, verifies:

- a clean checkout with `HEAD == GITHUB_SHA`;
- `GITHUB_ACTIONS=true`, `RUNNER_OS=Linux`, `RUNNER_ARCH=X64`, and `ImageOS=ubuntu24`;
- at least four logical CPUs, at least 15,000,000 KiB RAM, at least 6,000,000 KiB free
  in runner temp, and a soft `nofile` limit set to 65,536; and
- Rust `1.97.1` plus the actual runner/image/kernel/compiler/linker identity.

The job then verifies the already-pinned shadowsocks-rust archive before extraction,
builds all current binaries from the clean checkout, and runs the two modes in this
order on the same VM:

```sh
work="$RUNNER_TEMP/m4"
(
  set -euo pipefail
  ulimit -n 65536
  mkdir -p "$work/reference"
  curl --fail --location --retry 3 \
    --output "$work/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz" \
    https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz
  test "$(stat --format=%s "$work/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz")" = 11635096
  echo "5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65  $work/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz" | sha256sum -c -
  tar -xJf "$work/shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz" -C "$work/reference"
  cargo +1.97.1 build --workspace --bins --release --locked
  target/release/m4-qualification throughput \
    --sha "$GITHUB_SHA" \
    --sslocal "$work/reference/sslocal" \
    --ssserver "$work/reference/ssserver" \
    --output "$work/throughput.jsonl"
  target/release/m4-qualification resource \
    --sha "$GITHUB_SHA" \
    --output "$work/resource.jsonl"
)
```

Run throughput before resource qualification so the 10k drain's `TIME_WAIT` population
cannot affect the comparison. Success requires one bounded
`m4_performance_completion` line containing the medians/ratio, `sessions=10000`,
`samples=180`, `rss_windows=6/6`, `drain=PASS`, SHA, run ID, and run attempt. An `always`
cleanup step terminates owned processes, deletes `$RUNNER_TEMP/m4`, and fails if cleanup
cannot be proven. A failed or interrupted mode invalidates the whole job.

## Same-SHA repository and hosted gates

Before requesting remote scope, run the Full validation block serially on
`<accepted-integration-sha>` exactly as recorded in
`docs/agents/milestone-workflow.md`, then:

```sh
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git status --short
```

Those results are diagnostics. After explicit remote authorization only, push that
exact commit to an approved `codex/integration/**` ref and require one
`.github/workflows/m0.yml` run/attempt with performance, quality, MSRV, Windows MSVC,
Linux GNU, Linux musl, interop, and final qualification all successful. The interop
output MUST contain TCP `12/12` and UDP `12/12` with cleanup. No rerun, second push,
dispatch, PR, tag, release, or publication is authorized by this plan.

## Exit failures

- Any identity mismatch, timeout, missing sample, non-finite measurement, changing
  owner/task tuple, RSS-window violation, incomplete drain, early child exit, or leak.
- Raw evidence outside the allowed local/runner temp tree, an uploaded raw artifact,
  secret/destination output, failed temp cleanup, or a committed generated artifact.
- A failed/skipped full, test-budget, interop, platform, or blocking review gate.
- Evidence from WSL2, different SHAs, or different workflow attempts, or an unresolved
  P0/P1 blocker.
