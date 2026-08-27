# Workspace Policy Guidelines

`architecture.toml` is the declarative source for package ownership, dependency, fixture-consumer, and
boundary rules; `r0_policy.rs` evaluates the baseline workspace contract. `workflow_contract.rs` owns
the narrow workflow job/step parser and hosted-library execution chain; `hosted_pe_contract.rs` owns
the exact hosted-test executable and Windows import-deny proof. `required_job_contract.rs` owns the
typed required-job call surface, and `fuzz_workflow_contract.rs` owns impact, smoke, build, and bounded
campaign closure. `feature_topology_contract.rs` owns the
structured Cargo feature graph that keeps hosted-safe and fuzz builds free of the live backend.
Prefer structured metadata and behavioral mutation tests over source-text shape checks.

Update the policy in the same change as an intentional architecture move. Tests should report the
violated rule and exact owner or path.

Hosted TUN safety is a Rust build seam, not a source-token policy. Library-test builds must exclude
the live Windows adapter owner and FFI backend, selecting only target-neutral logic and injected or
fail-closed adapters. Keep privileged adapter, route, address, DNS, WFP, process-launch, and Hyper-V
operations behind production-only module declarations.

Mandatory hosted execution is a closed step-shape contract, not an existence check. Linux hosted
tests, each Windows hosted library test, deterministic smoke, and the sanitizer campaign must retain
their exact nonempty statement sequences; conditional wrappers and extra shell statements fail.

The fuzz impact ledger covers the entire fuzz crate. Only reviewed, typed Markdown globs may be
excluded; root-level build scripts, include sources, harnesses, corpora, and executable configuration
must remain campaign-triggering inputs.
