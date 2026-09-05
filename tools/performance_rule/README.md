# Rule performance controller

The entry point is `python -B -m tools.performance_rule`. The controller accepts
only current controller v6, reviewed calibration v2, and the current Rust runner
report. A/A collection never approves its own calibration; `review-calibration`
is an explicit operator action.

Before starting any A/B runner, the controller validates the complete reviewed
calibration and its hash-bound A/A source: raw mathematics, derived decisions,
runner identity, exact argument vector, execution policy and scenario catalog.
The source supplies the expected workload identity for the first and every later
runner report. That identity includes fixtures, configuration, measurement policy
and reported environment. Each report must also match the requested Rust profile
and complete configuration. Engine mode remains an observed implementation result.

Pass runner arguments after `--`. Supported measurement options are `--profile`,
`--samples`, `--iterations-per-sample`, `--include-100k`, `--workspace-root`, and
`--output`. Value options accept `--option value` or `--option=value`; duplicate,
unknown and abbreviated options are rejected. Help/version options do not collect
evidence and are not accepted as measurement arguments.

The default profile is `smoke`, with 101 samples and 8192 base iterations per
sample. Samples must be 5–1001; base iterations must be 1–10000000. Profile scales
are checked against the Rust producer:

| Profile | MatchSet | Route | DNS |
| --- | --- | --- | --- |
| smoke | 100 | 1, 32, 64 | 1 |
| qualification | 100, 1000, 10000 | 1, 32, 64, 1000, 10000 | 1, 64, 65, 100, 1000, 10000 |

`--include-100k` appends 100000 to MatchSet scales. Workspace and optional runner
output paths remain bound by the exact argument vector used for calibration.

`review-calibration --source-report source.json --reviewed-by NAME
--reviewed-utc UTC --output calibration.json` requires separate source and output
files in the same resolved directory. Cross-directory output is rejected before
writing; there is no implicit source copy. Keep the source alongside calibration.

Collection, JSON readers and final output share a 64 MiB encoded evidence bound.
Each prospective report is charged with its enclosing controller metadata and
trace before admission. Final comparisons and policy are checked before encoding
the complete document. If the next report or final summary cannot fit, collection
stops and emits an `INVALID` artifact retaining every previously admitted raw
report. The oversized report is not admitted. A partial artifact may contain a
half pair and cannot be reviewed as calibration. This is an encoded evidence
limit, not a process RSS guarantee. Output files are replaced atomically only
after the encoded document passes the bound.

Ordinary verification uses compact synthetic evidence and mocked runners only:

```text
python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v
```
