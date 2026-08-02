# TEST-0006 — M5 `shadowsocks-crypto` 迁移证据

- **Status:** Approved
- **Milestone:** M5
- **Spec:** `docs/specs/SPEC-0006-m5-shadowsocks-crypto-migration.md`
- **Gate profile:** strict

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M5-MUST-01 single implementation | architecture/workspace-policy source and metadata guards prove one normal backend and absence of old implementation symbols/edges | T02 product |
| M5-MUST-02 seam/method/config | existing public consumer compile + three-profile/config rejection tables + exact resolved feature set | T02 product |
| M5-MUST-03 TCP | existing KDF/AEAD/composite fixtures, auth negatives, and crate-private real-owner exhaustion table | T02 product |
| M5-MUST-04 UDP | existing primitive/composite packet tables, capacity/random/auth negatives, and terminal u64 counter table | T02 product |
| M5-MUST-05 zeroize/unsafe/errors | vendored delta review + feature graph + compile-time zeroize-owner assertions + redaction/negative suites | T01/T02 security |
| M5-MUST-06 protocol/interop | unchanged protocol sources + complete local protocol tests + hosted TCP/UDP `24/24` | T02/T03 |
| M5-MUST-07 dependency/MSRV/license/performance | exact provenance/lock/license report, Rust 1.85 gate, three platform rows, existing hosted performance job | T01/T03 |
| M5-MUST-08 close rule | one exact-SHA fail-closed qualification summary and zero blocking review findings | T03 release |

## T01 controlled dependency evidence

Primary review compares the exact crates.io 0.7.0 archive with committed vendor source,
then reviews only the ferrum patch delta. It verifies:

- version `0.7.0`、archive SHA-256、VCS commit、MIT LICENSE and provenance record;
- root edge is exact, no-default, `v2` only; vendor is excluded from workspace-wide
  `--all-features` so `v2-extra` cannot be enabled by the Full command;
- selected graph has no default/v1/v2-extra/reduced-round/ring/aws-lc and no unused
  `rand` edge;
- zeroize features and explicit temporary-buffer cleanup cover AES/GHASH/ChaCha/BLAKE3
  state used by selected v2;
- selected production path has no `unsafe` and exposes only the minimal checked/header
  operations required by the adapter;
- final resolved package identities/licenses are encoded by the existing
  `workspace_policy` seam rather than a new dependency scanner.

Focused commands after T01:

```powershell
cargo check -p ferrum2-crypto --all-targets --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo metadata --locked --format-version 1
cargo tree -p ferrum2-crypto -e features --locked
cargo +1.85.0 check -p ferrum2-crypto --all-targets --locked
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 product migration evidence

Reuse the existing tables; do not duplicate method × transport cases. Required focused
claims are:

- all pre-existing public crypto consumers compile without changes to
  `ferrum2-shadowsocks/src/**`;
- KDF/primitive/composite fixtures remain byte-exact for all three methods;
- tag flips/truncation/wrong widths/method mismatch/random/capacity failures preserve
  current closed errors and no accepted state;
- real `TcpSealer`/`TcpOpener` exhaustion for all three methods rejects before buffer
  mutation and remains rejected; authentication failure does not commit the nonce or
  admit plaintext, and the protocol owner terminates the flow;
- UDP packet `u64::MAX` succeeds once, the next seal rejects, and earlier failures do
  not consume the ID;
- debug/error/source/log sentinels contain no key, derived material, salt or nonce;
- source/metadata guards fail if old KDF/cipher code, a second backend edge, forbidden
  feature, fallback or runtime switch is reintroduced.

Focused commands after T02:

```powershell
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-config --locked
cargo test -p ferrum2-m0-harness --test architecture --test workspace_policy --locked
cargo clippy -p ferrum2-crypto -p ferrum2-shadowsocks --all-targets --all-features --locked -- -D warnings
cargo +1.85.0 check --workspace --all-targets --locked
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Integration and release evidence

Run the authoritative Full commands serially on the accepted integration candidate:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

After separate explicit push authorization, one `.github/workflows/m0.yml` push
run/attempt for that exact SHA must pass:

- quality / Full/security/process;
- Rust 1.85 MSRV;
- Windows MSVC、Linux GNU、Linux musl native rows;
- sing-box + shadowsocks-rust TCP `12/12` and UDP `12/12`, with cleanup;
- existing `performance` job, including positive medians/ratio, resource invariants,
  drain and cleanup;
- final qualification summary naming that SHA/run/attempt.

Performance remains diagnostic with no new numeric floor. A blocking reviewer must
accept the recorded result and dependency delta; an unexplained unacceptable regression
is a blocker, not permission to restore the old backend.

## Stop rules

- Any KAT, negative, feature, zeroize, unsafe, MSRV, license, dependency, platform,
  interop, performance, Full, budget or blocking review failure makes M5 `blocked`.
- Missing/skipped/provider-unavailable/unauthorized hosted evidence is `blocked`, not
  PASS and not a product rollback trigger.
- Existing M0-M4 runs are regression baselines only; results from another SHA/run/
  attempt cannot be spliced into M5 close evidence.
- One full Architect/QA review and one targeted re-review are the default bound.
