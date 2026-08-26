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

The qualification profile covers generated MatchSets at 100, 1,000, and
10,000 values; route programs at 1, 32, 64, 1,000, and 10,000 rules; and DNS
query programs at 1, 64, 65, 100, 1,000, and 10,000 rules. Add `--include-100k` to include the
explicitly expensive 100,000-value MatchSet scale:

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

Checked-in evidence is generated with:

```text
cargo run --release -p ferrum2-rule-qualification --locked -- \
  --profile qualification --include-100k --workspace-root . \
  --output tests/performance_rule/release-qualification.json
```

## Alternating A/A and parent/candidate runs

`tools/performance_rule.py` enforces at least five pairs. Release evidence uses
six pairs so process order is exactly balanced. The controller alternates run
order (`parent,candidate`, then `candidate,parent`), verifies the SHA-256
reported inside every run against the executable actually invoked, requires an
identical scenario-ID set, and retains all raw reports. Its v4 outer gate uses
only process-level p50 medians and derives a fail-closed suite catalog from
every raw measurement's explicit `suite` field. Only `match_set`
uses that outer median gate: A/A requires its median absolute paired noise at
or below 10%, and that observation calibrates its A/B limit between the 5%
local target and 10% noisy ceiling. Route-program and DNS-policy p50/p99 remain
complete observations because plan sections 17.2 and 17.3 specify coverage,
correctness, and scaling behavior without a universal percentage threshold.
Their counts and maxima are retained in the top-level policy summary.

Cross-process p99 for every suite is `observed_cross_process`, not a hard outer
gate. The final candidate's same-process paired qualification observations own
section 5.7's 5% median and 15% p99 MatchSet gates.

The release protocol retains 501 samples per scenario and uses Windows
`HIGH_PRIORITY_CLASS` (not realtime); the controller records that policy and
requires an exact argument and priority match between A/A and A/B. No raw
value is removed and the p99 estimator remains nearest-rank.

The checked-in history preserves the original v2 A/A diagnostic, the passing
v3 all-suite A/A, and the failed v3 all-suite A/B with all 19 route/DNS failed
comparisons. Canonical v4 A/A and A/B are deterministic offline scope
reclassifications. They record the source files' SHA-256, policies, decisions,
comparisons, failure IDs, and canonical raw-pair hashes. These archived files
are immutable provenance inputs: the controller verifies their source hashes
and unmodified raw pairs but exposes no v2/v3 conversion path. Generate fresh
canonical evidence with the current controller commands below.

Use the same binary for A/A calibration:

```text
python3 -B tools/performance_rule.py \
  --parent target/performance-rule-parent/ferrum2-rule-qualification.exe \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-aa.json \
  -- --profile smoke --samples 501 --workspace-root .
```

Use separate binaries for a parent/candidate observation with exactly the same
runner arguments and scenario set as the calibration:

```text
python3 -B tools/performance_rule.py \
  --parent /path/to/parent/ferrum2-rule-qualification \
  --candidate /path/to/candidate/ferrum2-rule-qualification \
  --calibration tests/performance_rule/release-aa.json \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-ab.json \
  -- --profile smoke --samples 501 --workspace-root .
```

Parent/candidate gating refuses to run without a passing A/A report from the
same parent runner SHA-256 and exact scenario/suite catalog. The MatchSet median
limit never exceeds 10%. A/B route/DNS medians and all cross-process p99 remain
diagnostic observations. For reclassified evidence, the controller re-reads
the named v2/v3 artifacts beside it and verifies every recorded complete-file
SHA-256.

The controller smoke is the bounded five-pair A/A and Parent/Candidate
MatchSet gate plus complete Route/DNS observations.
The candidate-only `--profile qualification --include-100k` command above is
the separate full matcher/Route/DNS matrix; do not mix its larger scenario set
with a smoke calibration.

Run controller contract tests with:

```text
python3 -B -m unittest discover -s tests/performance_rule -v
```
