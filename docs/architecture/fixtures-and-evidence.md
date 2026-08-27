# Fixture, Vendor and Evidence Ledger

Ordinary structural refactors do not edit the bytes or provenance in this ledger. Refreshes use a
standalone provenance change, independently reproduce the input, update every consumer and lock, and
record commands and hashes.

| Class | Canonical location | Identity and provenance contract | Consumers / execution boundary | Change rule |
|---|---|---|---|---|
| Config contract fixtures | `tests/fixtures/config` | v2 valid/rejection cohort, including unknown and invalid key length | config public contract tests | Add field-specific valid/invalid cases together; never weaken rejection |
| Platform config fixtures | `tests/platform/config` | process/native qualification inputs; intentionally differ from same-named root fixtures | `qualify_native.py` hosted evidence mode and local loopback-only `--local-contract` | Never deduplicate by filename; update binary behavior and platform qualification atomically |
| Crypto primitive vectors | `tests/fixtures/crypto` | `PROVENANCE.toml` binds source URL/revision, source and fixture hashes, rights, selected rows and independent generator hashes | crypto primitive/SIP022 tests; ordinary | Production Ferrum code must never be the oracle; preserve canonical LF and generator independence |
| SIP022 composite vectors | `tests/fixtures/sip022` | pinned spec revision/blob, fixture/generator hashes, exact primitive versions and GPL-owned synthetic bytes | Shadowsocks TCP/UDP tests; ordinary | No generated binaries/results or mutable upstream URL committed |
| SRS v2 binaries | `tests/fixtures/srs` | pinned `DustinWin/ruleset_geodata` commit, fetch date, lengths and SHA-256 in README | RuleSet loader/HTTPS tests and Rule qualification | Immutable until standalone refresh records commit, hash, length and generator version |
| DNS/RuleSet TLS credentials | `tests/fixtures/dns-tls` | synthetic `resolver.test` CA/cert/key, exact hashes, reproduction commands and test-only identity in the adjacent README | DNS encrypted-transport tests and the RuleSet HTTPS contract test | Shared stable input; never production trust; any refresh preserves provenance and atomically updates every consumer and digest |
| Reviewed TUN packet corpus | `crates/ferrum2-tun/tests/fixtures/packets` | canonical-LF synthetic packet rows, exact row count/bytes/SHA and independent construction | TUN parser/reassembly contract | Remains crate-owned and distinct from fuzz seeds |
| TUN fuzz seeds | `crates/ferrum2-tun/fuzz/corpus` | repository-owned seed hashes/counts in provenance; independent fuzz workspace/lock/nightly | hosted Linux runs deterministic smoke and a one-hour sanitizer campaign against four pure in-memory targets | A seed change updates provenance and smoke count/readback; campaign uses isolated corpus copies and retains evolved corpus/crash evidence |
| Vendored crypto patch | `vendor/shadowsocks-crypto` | crates.io 0.7.0 archive SHA `9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0`, packaged VCS `2affa6c39b30f7626137a1792c533610cf133ade`, MIT license and bounded delta in `FERRUM_PATCH.md` | root path patch; crypto only with default features off and `v2`; fuzz path patch | Ordinary refactor/format/Action-pin policy excludes vendor; intentional change replays archive diff and updates both locks |
| Root lock | `Cargo.lock` | locked root graph; patched `shadowsocks-crypto 0.7.0` has local source and reviewed dependency set | all root builds/tests | No unlocked update mixed with structural change |
| Fuzz lock/toolchain | `crates/ferrum2-tun/fuzz/{Cargo.lock,rust-toolchain.toml}` | independent graph; nightly `2026-07-10`; same local vendor patch | hosted deterministic smoke, libFuzzer compile, and sanitizer campaign | Update independently and verify locked offline metadata/compile after fetch |
| Linux performance raw evidence | GitHub Actions artifact referenced by reviewed policy | parent/candidate SHA, controller/policy/toolchain/runner identities, exact six-pair ABBA schedule, current plan/trial/summary schemas and bundle digest | manual performance only | 30-day artifact is temporary; durable URI/digest/expiry and refresh owner remain a gap |
| Windows TUN functional evidence | external approved evidence store | identity ledger schema 4; neutral controller bundle; main staged-input v6, guest-run v6, host-run v7 and campaign v1; hard static/staged/host v4; exported hashes, VM/`lab_checkpoint` identity and final Off | local approved host only; public `Core`, `Endurance`, or `Release` campaign plus independent hard-kill | Build candidate artifacts once; every profile gets a fresh transaction in fixed order; 28-file main and 21-file hard runtime closures (33/25 host sources) stay independent; cleanup failure invalidates success |
| Windows performance evidence | external approved evidence store + policy | independent 38-source performance closure including four hash-bound Lab runtime owners, runtime controller bundle, toolchain/image/`lab_checkpoint`, and A/A calibration identities | local approved host only | Qualification modules and verdicts are forbidden; thresholds remain calibration-required until reviewed A/A evidence exists |

## Vendor policy boundary

Only root `.github/workflows` are executable repository workflows. Nested
`vendor/shadowsocks-crypto/.github` files are upstream archive content: root Action-pin checks exclude
them, and they are not edited merely because they contain floating upstream tags. The executable
vendor policy instead verifies local patch resolution, v2-only features, selected exact RustCrypto
dependencies, VCS identity, absence of build scripts and unsafe tokens, plus both lockfiles.

## Evidence retention gap

The current performance workflow retains artifacts for 30 days. Before a milestone relies on an
artifact beyond that window, record an access-controlled durable URI, complete bundle SHA-256,
candidate/parent commits, workflow run/attempt, provider image, expiry and refresh owner. A summary or
policy decision is not a substitute for recoverable raw trials.
