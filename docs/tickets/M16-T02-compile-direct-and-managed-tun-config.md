---
id: M16-T02
milestone: M16
status: planned
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

- [ ] Missing type and explicit Shadowsocks preserve existing normalized output；direct rejects server/method/
      PSK，direct-only may omit global credentials，and proxy-bearing/legacy graphs retain M11 rules。
- [ ] Validated outbound state is one closed enum with no optional/sentinel endpoint or parallel credential
      vector；server configuration and schema v1 reject M16-only syntax redacted and side-effect-free。
- [ ] Every existing client composition consumer and test constructor compiles against that enum in this
      ticket。The Direct branch has a distinct pre-socket unsupported-execution error until T03 implements raw
      TCP/UDP；it MUST NOT be represented by a dummy server/key or reach resolver、socket、TUN or OS setup。
- [ ] Static/rule/final/selector/DNS detour can resolve singleton direct；every direct chain position and
      defensive mixed/empty invalidity fails before runtime。
- [ ] Auto-route/DNS defaults、relations、IPv4 prefix/address/count/output bounds and canonical include-minus-
      exclude `/1` plan match SPEC-0017，including default `0.0.0.0/0`、IPv6 route-prefix rejection、empty and
      257-row rejection。Auto-DNS requires only `ipv4_dns_address` and rejects `ipv6_dns_address` while retaining
      the existing M15 `ipv6_address` adapter field。
- [ ] TUN prefix overlap checks enumerate only actual physical endpoints：reachable physical first hops must
      resolve to IPv4；IPv6 concrete proxy and direct/no-detour DNS physical endpoints fail before OS calls，
      while proxy-detoured DNS uses the selected IPv4 concrete Shadowsocks first hop and may retain a logical
      IPv6 bootstrap without treating it as a separate physical socket；the synthetic IPv4 DNS address
      validates exactly。
- [ ] `--check-config` makes zero Windows/DLL/socket/thread calls。
- [ ] Table-driven config/selector/CLI evidence passes and test-footprint result is recorded。

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

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes only the additive fields/variants and restores the accepted T01 control。The main risks are
letting an invalid direct shape survive as optional endpoint/key state or leaving a temporarily uncompilable
consumer for T03；the closed enum、pre-socket refusal and workspace all-target check are the gate。
