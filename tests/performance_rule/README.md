# Rule performance evidence

This directory owns controller contract tests and checked-in smoke evidence for
`ferrum2-rule-qualification`.

`release-qualification.json` is the full qualification matrix, including the
explicit 100,000-value scale, deterministic exact/suffix/keyword/IPv4/IPv6/
mixed binary-SRS inputs, and the four pinned real SRS fixtures. The generated
inputs retain byte length, SHA-256, SRS version, decoded statistics, and
capabilities. An independently compiled synthetic reference proves structural
and behavioral equivalence; paired timing uses the exact decoded compiled
object through both source wrappers to exclude object-layout noise while
retaining materialization build and memory evidence. These are observations
from the recorded environment and dirty/clean tree state, not portable
baselines. Each report carries its enforced local gate decisions, actual batch
operation counts and durations, allocation observations, compiled net-retained
bytes, and runner SHA-256.
Regenerate it only with the exact command recorded in the tool README, after
running the Rust and Python contract tests.

The immutable evidence chain is:

- `release-aa-v2-p99-diagnostic.json`, the original failed cross-process p99
  A/A report, SHA-256
  `2b8f08988112c2142294a4266a24c8d7672d89f2387a91f4b460b52daaf7d4e9`;
- `release-aa-v3-all-suite-median.json`, the passing v3 all-suite A/A report,
  SHA-256
  `8e795edfc61c2328cb1f84fe0fd65f8ec0236d210078fb23c11e221cba87d394`;
- `release-ab-v3-all-suite-median-diagnostic.json`, the failed v3 A/B report,
  SHA-256
  `679a85722049e5dc0ea9fa601807623defc267be064d9bb4694aae0bf59719f3`;
- canonical v4 `release-aa.json` and `release-ab.json`, whose checked-in
  provenance records their historical deterministic derivation from those v3
  reports.

V4 derives each suite from the explicit `suite` field in every retained raw
measurement and fails closed for missing, inconsistent, or unknown suites.
Only `match_set` is subject to the calibrated cross-process median hard gate,
because plan section 5.7 defines the 5% local and 10% noisy equality limits for
ordinary-inline and RuleSet MatchSets. `route_program` and `dns_policy` are
complete observations under sections 17.2 and 17.3; those sections define
coverage, correctness, and scaling requirements but no universal percentage
gate. Their p50/p99 values and maxima remain in the top-level policy summary.

Cross-process p99 for every suite remains `observed_cross_process`. Section
5.7's 15% p99 hard gate is owned by the final candidate's same-process,
strictly alternating paired MatchSet rows in `release-qualification.json`.
Evidence binds that runner SHA-256 to the v4 A/B candidate.

Both outer reports retain six order-balanced pairs and 501 raw samples per
scenario. Reclassification preserves every raw pair, old comparison, old
decision, source-file SHA-256, and canonical raw-pair SHA-256. The original v3
A/B report's 19 failed route/DNS comparisons remain explicit provenance; v4
does not relabel them as passes.

The v2 and v3 files are immutable provenance inputs for validating the
checked-in v4 evidence only. The controller does not accept them as generation
inputs; new evidence is generated directly in the current v4 schema.

Generate A/A with the pinned parent:

```text
python3 -B tools/performance_rule.py \
  --parent target/performance-rule-parent/ferrum2-rule-qualification.exe \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-aa.json \
  -- --profile smoke --samples 501 --workspace-root .
```

Then generate A/B with the exact same arguments and process policy:

```text
python3 -B tools/performance_rule.py \
  --parent target/performance-rule-parent/ferrum2-rule-qualification.exe \
  --candidate target/release/ferrum2-rule-qualification.exe \
  --calibration tests/performance_rule/release-aa.json \
  --pairs 6 --runner-priority high \
  --output tests/performance_rule/release-ab.json \
  -- --profile smoke --samples 501 --workspace-root .
```

The controller requires exact runner-argument, priority, parent-SHA, scenario,
and suite agreement between calibration and A/B. It re-reads every named v2/v3
source artifact beside canonical evidence and requires each complete-file
SHA-256 to match provenance. The full candidate-only matrix remains in
`release-qualification.json` and owns the 5% median/15% p99 paired MatchSet
gate.
