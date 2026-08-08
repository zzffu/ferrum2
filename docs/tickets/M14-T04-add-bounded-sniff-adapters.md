---
id: M14-T04
milestone: M14
status: ready
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

- [ ] The module interface returns only closed progress/metadata values and owns no socket、Tokio task、
      route、egress、DNS query or telemetry destination。
- [ ] Hickory DNS、rustls ClientHello and httparse HTTP/1 behavior satisfies every fragmentation、
      malformed、header/question and exact-bound row in TEST-0015。
- [ ] Composite order/NeedMore arbitration prevents incomplete non-53 DNS and implausible TLS/HTTP prefixes
      from blocking another parser。
- [ ] `httparse = 1.10.1` no-default is the only new package identity；Hickory/rustls identities/features
      and Rust 1.88 remain exact。
- [ ] No handwritten parser、opaque fixture、dynamic registry、unsafe or config/runtime/binary dependency
      is introduced。
- [ ] T04 focused、Quick、footprint integrity and diff gates pass。

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

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes the new crate/member/dependency row。Parser ambiguity and unbounded incremental state are
the primary risks；every NeedMore path needs an exact byte ceiling and mutation witness。
