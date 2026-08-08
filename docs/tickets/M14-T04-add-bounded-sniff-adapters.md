---
id: M14-T04
milestone: M14
status: done
depends_on:
  - M14-T03
owns:
  - Cargo.lock
  - Cargo.toml
  - crates/ferrum2-sniff/**
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M14-T04 — Add bounded sniff adapters

## Outcome

Add one pure `ferrum2-sniff` module that recognizes strict DNS queries、TLS ClientHello and HTTP/1
requests from caller-owned bounded bytes through reviewed upstream parsers。

## Acceptance

- [x] The module interface returns only closed progress/metadata values and owns no socket、Tokio task、
      route、egress、DNS query or telemetry destination。
- [x] Hickory DNS、rustls ClientHello and httparse HTTP/1 behavior satisfies every fragmentation、
      malformed、header/question and exact-bound row in TEST-0015。
- [x] The generated/mutated ECH ClientHelloOuter row reports only rustls-observable outer public/cover
      SNI；no encrypted inner name is claimed and no second TLS/ECH parser is introduced。
- [x] Composite order/NeedMore arbitration prevents incomplete non-53 DNS and implausible TLS/HTTP prefixes
      from blocking another parser。
- [x] `httparse = 1.10.1` no-default is the only new package identity；Hickory/rustls identities/features
      and Rust 1.88 remain exact。
- [x] No handwritten parser、opaque fixture、dynamic registry、unsafe or config/runtime/binary dependency
      is introduced。
- [x] T04 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-sniff --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-sniff --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Result

- Commit: integration `11edd5d562fceb5892196ec2e209d285a8ceee83`；contract
  `f95870565128f4fe483dc0bb857588427b2dcb3c`；accepted product/test
  `920237a9a1c3e22ec2ceb2651378b7f01c1c0c18`。
- Review: final targeted Architect/QA `PASS`；`M14-T04-ARCH-001/002/003` and
  `QA-M14T04-001/002/003` closed。
- Footprint: zero-exit `REVIEW_REQUIRED`；integrity/category/ratio `PASS`；ticket
  case/support/fixture `+952/0/0`，code growth `+237`，ratio `1.755203`。
- Notes: one bounded repair closed HTTP fragmentation、DNS pre-allocation and physical-layout guard
  findings。ECH remained blocked，so two required independent `gpt-5.6-sol/xhigh` analyses ran to
  completion and both selected the same minimum correction：report only rustls-observable untrusted outer
  public/cover SNI，never claim the encrypted inner name，add one generated/mutated regression and keep
  production TLS code unchanged。Focused、Rust 1.88 and Quick `389/5` pass；no remote action。

## Rollback / risk

Rollback removes the new crate/member/dependency row。Parser ambiguity and unbounded incremental state are
the primary risks；every NeedMore path needs an exact byte ceiling and mutation witness。
