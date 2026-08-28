# Ferrum2 rule qualification

`ferrum2-rule-qualification` is a bounded, deterministic-input performance
runner for the shared rule engine and DNS policy state machine. It emits one
JSON document to stdout. `--output <file.json>` writes the same bytes to a
caller-selected file.

The default smoke profile is intentionally short:

```text
cargo run --release -p ferrum2-rule-qualification --locked -- \
  --profile smoke --workspace-root .
```

The qualification profile covers generated MatchSets at 64, 65, 100, 1,000,
and 10,000 values; route programs at 1, 32, 64, 1,000, and 10,000 rules; and
DNS query programs at 1, 64, 65, 100, 1,000, and 10,000 rules. The smoke
profile also retains the MatchSet 64/65 candidate boundary. Add `--include-100k`
to include the explicitly expensive 100,000-value MatchSet scale:

```text
cargo run --release -p ferrum2-rule-qualification --locked -- \
  --profile qualification --include-100k --workspace-root .
```

The MatchSet matrix contains exact, suffix, keyword, IPv4 CIDR, IPv6 CIDR,
and mixed generated inputs for ordinary inline and synthetic RuleSet sources.
Both sources are measured through `CompiledMatchSet`. The pinned `ads`, `ai`,
`cn`, and `cnip` binary SRS fixtures are strictly decoded and compiled, with
their hashes, versions, capabilities, and recovered entry counts recorded.

The qualification profile additionally constructs deterministic canonical SRS
v2 inputs for each of those six matcher categories at every configured
MatchSet scale. Each byte stream is hashed, strictly decoded by
`ferrum2_rule::srs::decode_srs`, compiled, and checked against an independently
compiled equivalent synthetic RuleSet. Paired timing then sends synthetic and
binary source wrappers to the exact same decoded `CompiledMatchSet`, so object
layout cannot masquerade as a matcher-backend regression. The rows retain the
independent materialization correctness, build-time, and compiled-memory
evidence and are subject to the same 5% median, 15% p99, and zero-match-
allocation gates. The smoke profile deliberately omits this expensive binary-
SRS matrix; every profile still exercises the complete Route observation
matrix used by the current product.

The generated ordinary and synthetic sources share the exact compiled object
during paired timing; the source-specific direct/snapshot materialization and
build evidence remain separate. Each real binary SRS matcher is likewise paired
against a synthetic snapshot reference to that exact decoded
`CompiledMatchSet`, covering `ads`, `ai`, `cn`, and `cnip` without memory-layout
noise.

Route measurements cover ordinary-only, RuleSet-only, and mixed constraints;
first, middle, last, and miss lookups; and the actual `SmallLinear` or
`Indexed` mode selected by the compiler. At every smoke and qualification
scale, additional mixed rows enable and consume the same selected-rule match
observation used by production metrics, including its allocation-free matcher
category recheck. DNS measurements cover ordinary and
RuleSet qname routing, CN-IP response hit/miss, cache hit/miss, and reuse of one
response across same-server continuation. Qname rows cover the 64/65 linear-to-
indexed boundary and 1,000/10,000 indexed scales; every row records the actual
program mode and query candidate visits, and indexed last-hit/miss probes must
remain sublinear. Response, cache, and continuation rows retain their bounded
1, 100, and 1,000 scales. All DNS rows report p50, p99, and queries/second.

Every latency sample, p50, p99, build time, environment fingerprint, git HEAD,
git tree and dirty-state digest, and runner SHA-256 is retained in JSON. Each
sample self-calibrates its operation count until at least 100 microseconds of
wall-clock work is measured, and records both the actual operation count and
the raw batch duration. The default 101 samples make p99 an observed tail value
rather than the maximum of a tiny sample set.

Ordinary and synthetic RuleSet rows are warmed up and measured as one pair in
the same process. Each retained pair sample contains 32 alternating rounds,
with each source first 16 times; a deterministic scenario hash chooses which
source starts. This makes every source receive the same operation count and
balances first-run, cache, timer, and scheduling effects before ns/op is
calculated.

An exactly pinned `stats_alloc` wrapper instruments the system allocator
through its safe API. Allocation accounting is outside the latency loop and
uses five separate one-operation regions, so allocator instrumentation cannot
distort p50/p99. Build regions report allocation counts and net retained
compiled bytes. MatchSet calls and Route evaluations with prepared scratch form
a hard zero-allocation gate; a non-zero result emits its JSON evidence and then
fails the process. DNS end-to-end rows include query construction and report
their measured allocations without pretending that construction is matcher
work.

The runner enforces the stable-local gates from plan section 5.7 on
`CompiledMatchSet` rows: ordinary/RuleSet median difference must be at most 5%,
p99 difference must be at most 15%, and every applicable matcher operation
must allocate zero times. Route and DNS program rows retain paired observations
and correctness results, but explicitly set `performance_gate_applicable` to
false because the 5%/15% matcher gate does not apply to whole-program dispatch.
The top-level `thresholds_passed` is true only when every applicable latency and
allocation gate passes. The runner emits complete JSON before returning
failure, so a failed qualification retains its evidence.

## Default-off rule candidates

The product and qualification runner default to the established sorted matcher
indexes and locked snapshot store. Three compile-time candidates are available
only for evidence collection:

- `candidate-domain-suffix-trie`
- `candidate-cidr-radix`
- `candidate-atomic-snapshot`

The runner forwards each feature to `ferrum2-rule`. Report schema v2 records the
sorted exact feature list under `candidate.enabled_features` and always records
`candidate.adoption_claim` as `false`. There is no production configuration
switch and a qualification result does not adopt a candidate.

Build the parent and candidates into separate directories so executable hashes
and feature identities stay bound to their reports:

```text
cargo build --release -p ferrum2-rule-qualification --locked \
  --target-dir target/performance-rule-parent
cargo build --release -p ferrum2-rule-qualification --locked \
  --features candidate-domain-suffix-trie \
  --target-dir target/performance-rule-domain-suffix-trie
cargo build --release -p ferrum2-rule-qualification --locked \
  --features candidate-cidr-radix \
  --target-dir target/performance-rule-cidr-radix
cargo build --release -p ferrum2-rule-qualification --locked \
  --features candidate-atomic-snapshot \
  --target-dir target/performance-rule-atomic-snapshot
cargo build --release -p ferrum2-rule-qualification --locked \
  --all-features --target-dir target/performance-rule-all-candidates
```

Use each candidate binary as a separate `--candidate` in the six-pair
controller flow below. Parent and candidate reports must have identical
scenarios, including the 64/65 boundary, and the controller rejects unknown,
duplicate, or unsorted feature identities. Adoption or rejection remains a
separate reviewed source change after calibrated evidence; thresholds and
decision semantics are unchanged.

External release evidence is generated with the following command, then
retained in the approved immutable evidence store and recorded by
`tests/performance_rule/fixtures/external-evidence-manifest-v1.json`:

```text
cargo run --release -p ferrum2-rule-qualification --locked -- \
  --profile qualification --include-100k --workspace-root . \
  --output tests/performance_rule/release-qualification.json
```

## Alternating A/A and parent/candidate runs

The only controller entry point is `python -B -m tools.performance_rule`.
The `run` command enforces exactly six pairs so parent/candidate process order
is one closed, balanced ABBA schedule. It validates every runner-reported
SHA-256 and scenario suite, retains all raw reports, and applies the outer median
gate only to `match_set`. Route/DNS medians and all cross-process p99 values
remain observations.

Production accepts only controller v6 and reviewed-calibration v2. A current A/A
run always returns `CALIBRATION_REQUIRED`; it cannot approve itself. Historical
v2/v3/v4 reports are immutable provenance and are understood only by the
test-owned archive verifier after complete-file hash verification.

Collect a current A/A calibration candidate:

```text
python3 -B -m tools.performance_rule run \
  --parent target/performance-rule-parent/ferrum2-rule-qualification.exe \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-aa-v6.json \
  -- --profile smoke --samples 501 --workspace-root .
```

After explicit review, create a separate source-hash-bound calibration artifact:

```text
python3 -B -m tools.performance_rule review-calibration \
  --source-report tests/performance_rule/release-aa-v6.json \
  --reviewed-by REVIEWER_ID --reviewed-utc YYYY-MM-DDTHH:MM:SSZ \
  --output tests/performance_rule/reviewed-aa-v2.json
```

Then run A/B with the same parent runner, arguments, priority, and scenario suite:

```text
python3 -B -m tools.performance_rule run \
  --parent /path/to/parent/ferrum2-rule-qualification \
  --candidate /path/to/candidate/ferrum2-rule-qualification \
  --calibration tests/performance_rule/reviewed-aa-v2.json \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-ab-v6.json \
  -- --profile smoke --samples 501 --workspace-root .
```

Without a reviewed current-schema calibration, A/B stops before runner execution.
The MatchSet median limit remains bounded by 10%; route/DNS and cross-process p99
remain diagnostic observations. The candidate-only qualification matrix remains
a separate runner invocation and must not be mixed with smoke calibration.

Run ordinary controller and compact evidence-contract tests with:

```text
python3 -B -m unittest discover -s tests/performance_rule -v
```
