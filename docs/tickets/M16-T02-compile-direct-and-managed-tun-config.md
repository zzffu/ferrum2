---
id: M16-T02
milestone: M16
status: done
depends_on:
  - M16-T01
owns:
  - crates/ferrum2-config/src/error.rs
  - crates/ferrum2-config/src/model.rs
  - crates/ferrum2-config/src/raw.rs
  - crates/ferrum2-config/src/validation.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/
  - tests/m0-harness/tests/config_cli.rs
---

# M16-T02 — Compile direct and managed-TUN configuration

## Outcome

Deliver the side-effect-free schema-v2 config vertical：a closed Direct/Shadowsocks client outbound model，
existing route/selector/DNS roots compiled to immutable singleton direct plans where allowed，fixed-chain
direct rejection，and a fully bounded canonical managed-TUN capture/DNS plan ready for runtime composition。

## Acceptance

- [x] Missing type and explicit Shadowsocks preserve existing normalized output；direct rejects server/method/
      PSK，direct-only may omit global credentials，and proxy-bearing/legacy graphs retain M11 rules。
- [x] Validated outbound state is one closed enum with no optional/sentinel endpoint or parallel credential
      vector；server configuration and schema v1 reject M16-only syntax redacted and side-effect-free。
- [x] Every existing client composition consumer and test constructor compiles against that enum in this
      ticket。The Direct branch has a distinct pre-socket unsupported-execution error until T03 implements raw
      TCP/UDP；it MUST NOT be represented by a dummy server/key or reach resolver、socket、TUN or OS setup。
- [x] Static/rule/final/selector/DNS detour can resolve singleton direct；every direct chain position and
      defensive mixed/empty invalidity fails before runtime。
- [x] Auto-route/DNS defaults、relations、IPv4 prefix/address/count/output bounds and canonical include-minus-
      exclude `/1` plan match SPEC-0017，including default `0.0.0.0/0`、IPv6 route-prefix rejection、empty and
      257-row rejection。Auto-DNS requires only `ipv4_dns_address` and rejects `ipv6_dns_address` while retaining
      the existing M15 `ipv6_address` adapter field。
- [x] Only with auto-route true，TUN prefix overlap checks enumerate actual physical endpoints：reachable first
      hops must resolve to IPv4；IPv6 concrete proxy and direct/no-detour DNS physical endpoints fail before OS
      calls，while proxy-detoured DNS uses the selected IPv4 concrete Shadowsocks first hop and may retain a
      logical IPv6 bootstrap without treating it as a separate physical socket。With auto-route false/omitted，
      the M15-compatible IPv6 proxy and absent/direct-detour DNS shape remains accepted without a managed
      physical-first-hop query；the synthetic IPv4 DNS address validates exactly when enabled。
- [x] `--check-config` makes zero Windows/DLL/socket/thread calls。
- [x] Table-driven config/selector/CLI evidence passes and test-footprint result is recorded。

## Validation

```sh
cargo test -p ferrum2-config --test config_contract --locked m16_
cargo test -p ferrum2-m0-harness --test config_cli --locked m16_
cargo test -p ferrum2-client m16_direct_pre_socket --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
sh scripts/test-budget.sh ticket --base <accepted-M16-T01-sha> --candidate <candidate-sha>
git diff --check <accepted-M16-T01-sha>..<candidate-sha>
```

## Result

- Bound base: `5630cf48ccd00f262a472e24ee135f2bac5a9cc0`。Initial candidate
  `6aff6cb33a29cf61cf483a26f45c80defbffbf26`（tree
  `38fc134774a2d31648e377f5c1505dc0a9bf5f2b`，parent `5630cf48…`）compiled the closed config model。
  Bounded product repair `6edba67068fecdb815dfd51bc321d50e924f16bc`（tree
  `554cc07f823eb489b8a708893e785caf4bb8fd01`，parent `6aff6cb…`）and final reviewed test-only candidate
  `136dbe280a242c0a93fcc122f1c70ad58294158f`（tree
  `5720b1752024c025c098b3fb5273a6a49d7fe4dd`，parent `6edba670…`）close the product/test work。Docs
  closeout `5782c08c443a5ed8adfc81841beeaec345611811` was the first pushed T02 integration；final local repaired
  candidate `13b6d681d282cdd054c0c52f4fded01d7e5b2124`（tree
  `c8cf7dfc13d1e6ae56d6aa12167907fa807ae1c3`，parent `5782c08…`）contains only the mechanical one-file
  Clippy repair（`+3/-2`）。
- Review history: initial Architect `BLOCK` identified the sentinel/parallel credential vector and catalog-level
  Direct rejection instead of selected-plan classification（`ARCH-001/002`）；Architect/QA also requested the
  compact boundary and real zero-side-effect snapshot evidence（`ARCH-003`、`QA-001/002`）。`6edba670…`
  validates directly into the closed enum and classifies the selected snapshot before TCP/UDP side effects。
  Targeted review retained only `M16T02-RR-001` / `ARCH-003` test evidence：enabled raw exclude counts and
  deterministic include rows were not independently asserted。Root diagnosed this as test-only；`136dbe280…`
  extends the existing table without product、helper or harness changes。Final Architect and QA reviews of exact
  `136dbe280…` are both `PASS_WITH_NOTES` with zero blocker/major/minor；the sole accepted note is the numeric
  footprint advisory。Architect and QA reviews of exact repaired candidate `13b6d681…` are both `PASS` with
  zero blocker/major/minor；QA also reports zero note，and all prior findings remain closed。
- Validation: focused config `4/4`、client Direct pre-socket `1/1`、side-effect-free CLI `1/1`；full config
  `33`、full client `50`、full CLI `8`、architecture `19`；workspace all-target check was warning-free and
  formatting、diff、normal hook all passed。QA's full workspace regression also passed。For `13b6d681…`，exact
  package and authoritative workspace Clippy are warning-free；focused config `4/4`、full config `33`、
  architecture `19`、format、workspace all-target、hook and diff all pass。
- Footprint: integrity `PASS`，numeric `REVIEW_REQUIRED` advisory；code/tests `30096/51191`，ratio
  `1.700924 PASS`；case/support/fixture `45442/5152/597`，ticket deltas `+756/0/0` and code growth `+325`。
  The advisory is accepted because the growth is distinct contract evidence in existing tables/seams with zero
  support/fixture growth and no duplicate helper or harness。
- Hosted evidence: the first T02 non-force push moved `master` from `5630cf4…` to `5782c08…` with exact remote
  readback。Automatic push run `31443577764/1` is preserved as `failure` and was not rerun。MSRV、interop、
  test-footprint、Linux musl、Windows MSVC、Linux GNU and Windows TUN E2E succeeded；quality failed only at
  authoritative Full Clippy on the three deterministic `validation.rs` lints（`too_many_arguments`、
  `map_clone`、`redundant_closure`），so qualification failed closed。Performance and Windows TUN performance
  were skipped by the push event；there was no hidden second failure。
- Remote/integration: `13b6d681…` is not claimed integrated、pushed or hosted-PASS。The failed run was not
  rerun，and no dispatch、force-push、PR、tag、package、release or publication occurred。Required future
  non-force pushes，including performance-related pushes，remain explicitly authorized。

## Rollback / risk

Rollback removes only the additive fields/variants and restores the accepted T01 control。The main risks are
letting an invalid direct shape survive as optional endpoint/key state or leaving a temporarily uncompilable
consumer for T03；the closed enum、pre-socket refusal and workspace all-target check are the gate。
